/*
 *  assd.c - Advanced Security SD Extension
 *
 *  Copyright 2011 Giesecke & Devrient GmbH.  All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *  Detailed information about the Advanced Security SD Extension (ASSD) can
 *  be found in
 *  [A1] "SD Specifications Part A1  Advanced Security SD Extension Simplified
 *       Specification"
 *  provided by the SD Card Association.
 *  Detailed information about the SD can be found in
 *  [1] "SD Specifications Part 1  Physical Layer Simplified Specification"
 *
 */

#define VERSION "120919f"

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/timer.h>

#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/scatterlist.h>

extern int mmc_sd_switch(struct mmc_card *card, int mode, int group, u8 value,
			 u8 *resp);

/*
 * internal definitions
 */
#define SWITCH_CHECK_FUNCTION   0
#define SWITCH_SET_FUNCTION     1
#define SWITCH_GROUP_2          1

/*
 * Currently we support only blocking SEC_R/W, no CL_support & PMEM_support !
 */
#define SWITCH_ASSD_1_1         (1 << 0)
#define SWITCH_ASSD_2_0         (1 << 2)
#define ASSD_SEC_SYSTEM         1

#define ASSD_SEND_STOP          (1 << 0)

static u8                 *assd_block;
static u8                  assd_timeout_flag;
static unsigned long       assd_status;
static struct semaphore    assd_lock;

static unsigned int        assd_timeout;
static struct assd_system {
	u8                     state;
	u8                     Version;
	unsigned int           Nsrl;
	unsigned int           Nswb;
	unsigned int           Nwsb;
	// will be later expand for ASSD 2.0+, PMEM-R/W and new features
} assd_system;

/*
 * A Secure Token is composed of the Command or Response APDU prefixed
 * with a Secure Token Length field (2 bytes).
 * Currently we do not support Secure Tokens with a length exceeding the
 * defined block length (512 bytes). See [A1] chapter "Secure Tokens"
 * for more information.
 */
#define MAX_LENGTH              510

/*
 * Additional commands as defined in [A1] chapter "Commands".
 */
#define ASSD_READ_SEC_CMD       34
#define ASSD_WRITE_SEC_CMD      35
#define ASSD_SEND_PSI           36
#define ASSD_CONTROL_SYSTEM     37
//#define ASSD_DIRECT_SEC_READ    50
//#define ASSD_DIRECT_SEC_WRITE   57

#define ASSD_PSI_SR             0
#define ASSD_PSI_PR             4
//#define ASSD_PSI_RNR            6

#define ASSD_CONTROL_RESET      1

#define ASSD_SR_STATE_IDLE      0
#define ASSD_SR_STATE_INPROC    1
#define ASSD_SR_STATE_COMPLETE  2
#define ASSD_SR_STATE_ABORTED   3

/*
 * todo: hopefully the host never is removed!
 */
static struct mmc_host     *assd_host;
static struct timer_list    assd_timer;

#if !defined(DEBUG)
#define pr_debug_hexstr(buf, len)
#else

static void pr_debug_hexstr(char *buf, int len)
{
	int  i;
	char s[2048];

	snprintf(s, sizeof(s), "assd: ");
	for (i = 0; i < len; i++)
		snprintf(s + strlen(s), sizeof(s) - strlen(s), "%.2x",
			 (unsigned char)buf[i]);
	snprintf(s + strlen(s), sizeof(s) - strlen(s), "\n");
	/*
	 * Since printk() is limited to 1023 characters per call...
	 */
	printk(KERN_DEBUG "%s", s);
	if (strlen(s) >= 1023)
		printk(KERN_DEBUG "%s", s + 1023);
}

#endif /* DEBUG */

/*
 * internal: send SET_BLK_LEN with argument
 */
static int assd_set_blksize(struct mmc_host *host, int blksize)
{
	struct mmc_command cmd;
	int                ret;

	BUG_ON(!host);
	cmd.opcode = MMC_SET_BLOCKLEN;
	cmd.arg    = blksize;
	cmd.flags  = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_AC;
	mmc_claim_host(host);
	if (host->card == NULL) {
		ret = -ENODEV;
		goto out;
	}
	ret = mmc_wait_for_cmd(host, &cmd, 5);
out:
	mmc_release_host(host);
	return ret;
}

/*
 * internal: send CONTROL_ASSD_SYSTEM with argument
 */
static int assd_control(struct mmc_host *host, int arg)
{
	struct mmc_command cmd;
	int                ret;

	BUG_ON(!host);
	cmd.opcode = ASSD_CONTROL_SYSTEM;
	cmd.arg    = arg;
	cmd.flags  = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;
	mmc_claim_host(host);
	if (host->card == NULL) {
		ret = -ENODEV;
		goto out;
	}
	ret = mmc_wait_for_cmd(host, &cmd, 5);
out:
	mmc_release_host(host);
	return ret;
}

/*
 * internal: send SEND_PSI with register-ID
 */
static int assd_send_psi(struct mmc_host *host, int reg)
{
	struct mmc_request req;
	struct mmc_command cmd;
	struct mmc_data    dat;
	struct scatterlist sg;

	BUG_ON(!host);
	memset(&req, 0, sizeof(struct mmc_request));
	memset(&cmd, 0, sizeof(struct mmc_command));
	memset(&dat, 0, sizeof(struct mmc_data));
	req.cmd    = &cmd;
	req.data   = &dat;
	cmd.opcode = ASSD_SEND_PSI;
	cmd.arg    = reg;
	cmd.flags  = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	dat.blksz  = 32;
	dat.blocks = 1;
	dat.flags  = MMC_DATA_READ;
	dat.sg     = &sg;
	dat.sg_len = 1;
	sg_init_one(&sg, assd_block, 32);
	mmc_claim_host(host);
	if (host->card == NULL) {
		mmc_release_host(host);
		return -ENODEV;
	}
	/*
	 * here Nac (from MMC) is to use for timeout
	 */
	mmc_set_data_timeout(&dat, host->card);
	mmc_wait_for_req(host, &req);
	mmc_release_host(host);
	if (cmd.error)
		return cmd.error;
	if (dat.error)
		return dat.error;
	return 0;
}

/*
 * internal: send SWITCH for group-2 and check status bits depending on CHECK/SET mode
 */
static int assd_switch(struct mmc_host *host, int mode, int func)
{
	int              ret = 0;
	struct mmc_card *card;

	BUG_ON(!host);
	pr_debug("assd: assd_switch()\n");
	mmc_claim_host(host);
	card = host->card;
	if (card == NULL) {
		ret = -ENODEV;
		goto out;
	}
	/*
	 * SD memory cards compatible with versions earlier than SD 1.10 do not
	 * support the Switch function command.
	 */
	if (!card->scr.sda_vsn) {
		ret = -ENODEV;
		goto out;
	}
	/*
	 * See [1] chapter "Switch Function Command" for information
	 * about modes, groups, and functions.
	 */
	mmc_sd_switch(card, mode, SWITCH_GROUP_2, func, assd_block);
	/*
	 * We verify the response only if we checked/switched to a non-default
	 * function.
	 */
	if (func) {
		if (mode == SWITCH_SET_FUNCTION) {
			/*
			 * See [1] chapter "Switch Function Status" for information
			 * about the status bits. The function was successfully
			 * switched if bits 383:380 hold the function number,
			 * and in bits 431:416 the function group information show
			 * that our function is supported.
			 */
			if (!(assd_block[11] & (1 << func))) {
				ret = -ENODEV;
				goto out;
			}
			if ((assd_block[16] & 0xf0) != (func << 4)) {
				ret = -ENODEV;
				if ((assd_block[17] == 0x01) && (assd_block[27] & (1 << func)))
					ret = -EBUSY;
				goto out;
			}
		} else {
			/*
			 * See [1] chapter "Switch Function Status" for information
			 * about the status bits. In bits 431:416 the function group 
			 * information show that our function is supported.
			 */
			if (!(assd_block[11] & 
				((1 << SWITCH_ASSD_2_0) | (1 << SWITCH_ASSD_1_1)))) {
				ret = -ENODEV;
				goto out;
			}
		}
	}
out:
	mmc_release_host(host);
	return ret;
}

/*
 * internal: initialize the enabled ASSD system 
 */
static int assd_initSecSys(struct mmc_host *host)
{
	int ret = 0;;

	if (assd_set_blksize(host, 32)) {
		printk(KERN_WARNING "assd: set blocklength (32) failed\n");
		/*
		 * Some cards to not support SET_BLOCKLENGTH, but
		 * accept SEND_PSI with a block length of 512. For this
		 * reason we do not return an error but continue.
		 */
		/* return -EIO; */
	}
	ret = assd_send_psi(host, ASSD_PSI_PR);
	if (ret) {
		printk(KERN_WARNING "assd: card does not sent properties\n");
		ret = -ENODEV;
		goto out;
	}
	/*
	 * read Version, ASSD_Nsrl & ASSD_Nswb in minimum
	 * from properties
	 */
	assd_system.Version = assd_block[2];
	assd_system.Nsrl    = assd_block[0];
	assd_system.Nswb    = assd_block[1];
	assd_system.Nwsb    = 0;
	if (assd_system.Version > 0)
		assd_system.Nwsb    = assd_block[7];
	if (assd_system.Version > 1) {
		if (!((int)(assd_block[12] << 8 | assd_block[13]) & (1 << ASSD_SEC_SYSTEM))) {
			printk(KERN_INFO "assd: card does not support ASSD security system\n");
			ret = -ENODEV;
			goto out;
		}
		ret = assd_send_psi(host, ASSD_PSI_SR);
		if (ret) {
			printk(KERN_WARNING "assd: card does not sent status during init ASSD\n");
			ret = -ENODEV;
			goto out;
		}
		/*
		 * we alltimes enable/reset the ASSD 2+ security system on init
		 */
		ret = assd_control(host, (ASSD_SEC_SYSTEM << 8) | ASSD_CONTROL_RESET);
		if (ret) {
			printk(KERN_WARNING "assd: card does not react on activate/reset ASSD security system\n");
			ret = -ENODEV;
			goto out;
		}
		if (assd_block[6] != ASSD_SEC_SYSTEM) {
			/*
			 * ASSD was not the current active security system after init,
			 * we have to check if its now enabled after activate/reset
			 */
			ret = assd_send_psi(host, ASSD_PSI_SR);
			if (ret) {
				printk(KERN_WARNING "assd: card does not sent status after selecting ASSD\n");
				ret = -ENODEV;
				goto out;
			}
			if (assd_block[6] != ASSD_SEC_SYSTEM) {
				printk(KERN_WARNING "assd: card does not activate ASSD security system\n");
				ret = -ENODEV;
				goto out;
			}
		}
	} else {
		/*
		 * we alltimes enable/reset the ASSD 1.1 security system on init
		 */
		ret = assd_control(host, ASSD_CONTROL_RESET);
		if (ret) {
			printk(KERN_WARNING "assd: card does not react on reset ASSD security system\n");
			return -ENODEV;
		}
	}
out:
	if (assd_set_blksize(host, 512)) {
		printk(KERN_WARNING "assd: set blocklength (512) failed\n");
		/*
		 * Some cards to not support SET_BLOCKLENGTH, but
		 * accept SEND_PSI with a block length of 512. For this
		 * reason we do not return an error but continue.
		 */
		/* return -EIO; */
	}
	return ret;
}

/*
 * internal: enabled ASSD system
 */
static int assd_enable(struct mmc_host *host)
{
	int i = 0;
	int ret, sver;

	pr_debug("assd: assd_enable()\n");
	/*
	 * we have to try multiple times to enable ASSD by SD_SWITCH command
	 * (See [1] chapter "Switch Function")
	 */
	do {
		/*
		 * Check if the card was removed.
		 */
		if (assd_host == NULL) {
			printk("assd: failed to enable ASSD\n");
			return -ENODEV;
		}
		ret = assd_switch(host, SWITCH_CHECK_FUNCTION, 0xF);
		if (ret) {
			printk(KERN_INFO "assd: card does not support ASSD\n");
			return -ENODEV;
		}
		if (assd_block[11] & (1 << SWITCH_ASSD_2_0))
			sver = SWITCH_ASSD_2_0;
		else
			sver = SWITCH_ASSD_1_1;
		ret = assd_switch(host, SWITCH_SET_FUNCTION, sver);
		if (!ret) {
			ret = assd_initSecSys(host);
			if (ret)
				return -ENODEV;
			printk(KERN_INFO "assd: the ASSD capable card is ready for use\n");
			assd_system.state = 1;
			return 0;
		}
		msleep_interruptible(16);
	} while (++i < 100);
	/*
	 * it was impossible to enable ASSD by multiple loops
	 * (we do not loop inifite!)
	 */
	assd_system.state = 0;
	if (ret == -EBUSY)
		printk(KERN_INFO "assd: failed, card is still busy\n");
	else
		printk(KERN_INFO "assd: failed to enable ASSD\n");
	return -ENODEV;
}

/*
 * internal: send secure write command with data (assd_block)
 */
static int assd_write_sec_cmd(struct mmc_host *host)
{
	struct mmc_request req;
	struct mmc_command cmd;
	struct mmc_command stp;
	struct mmc_data    dat;
	struct scatterlist sg;

	BUG_ON(!host);
	memset(&req, 0, sizeof(struct mmc_request));
	memset(&cmd, 0, sizeof(struct mmc_command));
	memset(&stp, 0, sizeof(struct mmc_command));
	memset(&dat, 0, sizeof(struct mmc_data));
	req.cmd    = &cmd;
	req.data   = &dat;
	if (test_bit(ASSD_SEND_STOP, &assd_status))
		req.stop = &stp;
	cmd.opcode = ASSD_WRITE_SEC_CMD;
	cmd.arg    = 1;
	cmd.flags  = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	dat.blksz  = 512;
	dat.blocks = 1;
	dat.flags  = MMC_DATA_WRITE;
	dat.sg     = &sg;
	dat.sg_len = 1;
	sg_init_one(&sg, assd_block, 512);
	stp.opcode = MMC_STOP_TRANSMISSION;
	stp.arg    = 0;
	stp.flags  = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;
	mmc_claim_host(host);
	if (host->card == NULL) {
		mmc_release_host(host);
		return -ENODEV;
	}
	/*
	 * here Nwsb (from PSI-PR) or default is to use for timeout
	 */
	if (assd_system.Nwsb != 0) {
		dat.timeout_ns   = assd_system.Nwsb * 250 * 1000000;
		dat.timeout_clks = 0;
	} else
		mmc_set_data_timeout(&dat, host->card);
	mmc_wait_for_req(host, &req);
	mmc_release_host(host);
	if (cmd.error)
		return cmd.error;
	if (dat.error)
		return dat.error;
	/*
	 * Do not send any STOP_TRANSMISSION command from now on,
	 * if this card does not require a STOP_TRANSMISSION command.
	 */
	if (stp.error == -ETIMEDOUT)
		clear_bit(ASSD_SEND_STOP, &assd_status);
	return 0;
}

/*
 * internal: send secure read command and read data (assd_block)
 */
static int assd_read_sec_cmd(struct mmc_host *host)
{
	struct mmc_request req;
	struct mmc_command cmd;
	struct mmc_command stp;
	struct mmc_data    dat;
	struct scatterlist sg;

	BUG_ON(!host);
	memset(&req, 0, sizeof(struct mmc_request));
	memset(&cmd, 0, sizeof(struct mmc_command));
	memset(&stp, 0, sizeof(struct mmc_command));
	memset(&dat, 0, sizeof(struct mmc_data));
	req.cmd    = &cmd;
	req.data   = &dat;
	if (test_bit(ASSD_SEND_STOP, &assd_status))
		req.stop = &stp;
	cmd.opcode = ASSD_READ_SEC_CMD;
	cmd.arg    = 1;
	cmd.flags  = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	dat.blksz  = 512;
	dat.blocks = 1;
	dat.flags  = MMC_DATA_READ;
	dat.sg     = &sg;
	dat.sg_len = 1;
	sg_init_one(&sg, assd_block, 512);
	stp.opcode = MMC_STOP_TRANSMISSION;
	stp.arg    = 0;
	stp.flags  = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;
	mmc_claim_host(host);
	if (host->card == NULL) {
		mmc_release_host(host);
		return -ENODEV;
	}
	/*
	 * here Nsrl (from PSI-PR) or default is to use for timeout
	 */
	if (assd_system.Nsrl != 0) {
		dat.timeout_ns   = assd_system.Nsrl * 250 * 1000000;
		dat.timeout_clks = 0;
	} else
		mmc_set_data_timeout(&dat, host->card);
	mmc_wait_for_req(host, &req);
	mmc_release_host(host);
	if (cmd.error)
		return cmd.error;
	if (dat.error)
		return dat.error;
	return 0;
}

/*
 * internal: timer call-back function for Nswb handling in assd_process()
 */
void assd_timer_cb( unsigned long data )
{
	pr_debug("assd: timeout event !\n");
	assd_timeout_flag = 1;
}

/*
 * internal: send command, check status and read response
 */
static int assd_process(struct mmc_host *host, unsigned char __user *buf)
{
	int          ret;
	unsigned int count;

	BUG_ON(assd_timeout <= 0);
	/*
	 * check status by reading PSI_SR, take care (using CONTROL_RESET) ASSD is idle
	 */
	(void)assd_set_blksize(host, 32);
	count = 0;
	do {
		ret = assd_send_psi(host, ASSD_PSI_SR);
		if (ret) {
			printk(KERN_WARNING "assd: status can not be checked for idle\n");
			return -EIO;
		}
		if (assd_block[0] != ASSD_SR_STATE_IDLE) {
			count++;
			ret = assd_control(host, (assd_system.Version > 1)? (ASSD_SEC_SYSTEM << 8) | ASSD_CONTROL_RESET : ASSD_CONTROL_RESET);
			if (ret) {
				printk(KERN_WARNING "assd: card does not react on enter idle state\n");
				return -ENODEV;
			}
		}
	} while ((assd_block[0] != ASSD_SR_STATE_IDLE) && (count < 8));
	if (count >= 8) {
		printk(KERN_WARNING "assd: card is not able to enter into idle state\n");
		return -ENODEV;
	}
	(void)assd_set_blksize(host, 512);
	/*
	 * Copy secure token (STL + C-APDU). See [A1] chapter "Secure Tokens".
	 */
	if (copy_from_user(assd_block, buf, 512))
		return -EFAULT;
	count = ((buf[0] << 8) + buf[1]) - 2;
	if (count > MAX_LENGTH)
		return -EINVAL;
	if (count < 4) {
		printk(KERN_WARNING "assd: command apdu too short\n");
		return -EINVAL;
	}
	pr_debug_hexstr(&assd_block[2], count);
	/*
	 * send command / C-APDU
	 */
	ret = assd_write_sec_cmd(host);
	if (ret) {
		printk(KERN_WARNING "assd: send command apdu failed\n");
		return -EIO;
	}
	/*
	 * start timer for waiting on status to be get complete
	 */
	assd_timeout_flag = 0;
	(void)setup_timer(&assd_timer, assd_timer_cb, 0 );
	ret = mod_timer(&assd_timer, jiffies + msecs_to_jiffies(assd_system.Nswb * 250) );
	if (ret) {
		printk(KERN_WARNING "assd: error in timer setup\n");
		return -EFAULT;
	}
	/*
	 * set block size for polling PSI_SR
	 */
	if (assd_set_blksize(host, 32)) {
		printk(KERN_WARNING "assd: set blocklength (32) failed\n");
		/*
		 * Some cards to not support SET_BLOCKLENGTH, but
		 * accept SEND_PSI with a block length of 512. For this
		 * reason we do not return an error but continue.
		 */
		/* return -EIO; */
	}
	/*
	 * Check if R-APDU is ready with Nswb timeout. See [A1] chapter
	 * "ASSD Status Register (ASSD-SR)".
	 */
	do {
		ret = assd_send_psi(host, ASSD_PSI_SR);
		if (assd_block[0] != 1)
			break;
		msleep_interruptible(4);
	} while ((!ret) && (assd_timeout_flag == 0) && (assd_host != NULL));
	(void)del_timer_sync(&assd_timer);
	if (assd_set_blksize(host, 512)) {
		printk(KERN_WARNING "assd: set blocklength (512) failed\n");
		/*
		 * Some cards to not support SET_BLOCKLENGTH, but
		 * accept SEND_PSI with a block length of 512. For this
		 * reason we do not return an error but continue.
		 */
		/* return -EIO; */
	}
	if ((ret != 0) || (assd_host == NULL)) {
		printk(KERN_WARNING "assd: card not reacting or lost in secure sequence\n");
		return -ENODEV;
	}
	if (assd_block[0] != ASSD_SR_STATE_COMPLETE) {
		switch (assd_block[0]) {
			case ASSD_SR_STATE_IDLE:
				printk(KERN_WARNING "assd: no secure sequence active\n");
				break;
			case ASSD_SR_STATE_INPROC:
				printk(KERN_WARNING "assd: timeout in secure secuence\n");
				break;
			case ASSD_SR_STATE_ABORTED:
				printk(KERN_WARNING "assd: secure sequence aborted\n");
				break;
			default:
				printk(KERN_WARNING "assd: unknown error in secure sequence (%d)\n", assd_block[0]);
				break;
		}
		ret = assd_control(host, (assd_system.Version > 1)? (ASSD_SEC_SYSTEM << 8) | ASSD_CONTROL_RESET : ASSD_CONTROL_RESET);
		if (ret) {
			printk(KERN_WARNING "assd: card does not react on reset secure sequence\n");
			return -ENODEV;
		}
		if (assd_block[0] == ASSD_SR_STATE_INPROC)
			return -ETIMEDOUT;
		return -EIO;
	}
	/*
	 * get response / R-APDU
	 */
	ret = assd_read_sec_cmd(host);
	if (ret) {
		printk(KERN_WARNING "assd: get resonse apdu failed\n");
		return -EIO;
	}
	/*
	 * Get secure token length (STL). See [A1] chapter "Secure Tokens".
	 */
	count = assd_block[1] + (assd_block[0] << 8) - 2;
	if (count > MAX_LENGTH)
		count = MAX_LENGTH;
	pr_debug_hexstr(&assd_block[2], count);
	/*
	 * Copy secure token (STL + R-APDU). See [A1] chapter "Secure Tokens".
	 */
	if (copy_to_user(buf, assd_block, count + 2))
		return -EFAULT;
	return 0;
}

/*
 * IOCTL-interface to public functionality
 */
#include "assd.h"

static long assd_ioctl(struct file *file, unsigned int nr, unsigned long arg)
{
	struct mmc_host *host = assd_host;
	long ret = 0;

	pr_debug("assd: assd_ioctl(%d)\n", nr);
	/*
	 * Check if a assd capable card is ready.
	 * Only VERSION, TIMEOUT & WAIT will executed without capable card
	 */
	if ((host == NULL) && (nr != ASSD_IOC_GET_VERSION) &&
						  (nr != ASSD_IOC_SET_TIMEOUT) &&
						  (nr != ASSD_IOC_WAIT)) {
		printk(KERN_INFO "assd: no assd capable card was found\n");
		return -ENODEV;
	}
	switch (nr) {
		case ASSD_IOC_ENABLE:
		case ASSD_IOC_TRANSCEIVE:
#ifdef CONFIG_MMC_BLOCK_DEFERRED_RESUME
			if (mmc_bus_needs_resume(host)) {
				mmc_resume_bus(host);
				(void)assd_set_blksize(host, 512);
			}
#endif
			if (down_trylock(&assd_lock))
				return -EBUSY;
			if (nr == ASSD_IOC_ENABLE)
				ret = assd_enable(host);
			else
				ret = assd_process(host, (unsigned char *)arg);
			up(&assd_lock);
			break;
		case ASSD_IOC_WAIT:
			if (host == NULL) {
				int timeout = (1000 / 16) + 1;
				if (arg) timeout = (arg / 16) + 1;
				for (; timeout > 0; timeout--) {
					if (assd_host != NULL)
						return 0;
					msleep_interruptible(16);
				}
				ret = -ETIMEDOUT;
			}
			break;
		case ASSD_IOC_PROBE:
			break;
		case ASSD_IOC_SET_TIMEOUT:
			if ((int)arg <= 0)
				return -EINVAL;
			assd_timeout = (arg / 16) + 1;
			break;
		case ASSD_IOC_GET_VERSION:
			if (copy_to_user((char __user *)arg, VERSION, 8))
				ret = -EFAULT;
			break;
		default:
			ret = -EINVAL;
			break;
	}
	return ret;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = assd_ioctl,
};

static struct miscdevice dev = {
	.name = "assd",
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &fops,
};

static struct miscdevice dev_inserted = {
	.name = "assdinserted",
	.minor = MISC_DYNAMIC_MINOR,
	.fops = NULL,
};

static int assd_probe(struct mmc_card *card)
{
	pr_debug("assd: assd_probe()\n");
	/*
	 * Currently we support one assd capable card only.
	 */
	if (assd_host != NULL)
		return -ENODEV;
#ifdef CONFIG_MMC_BLOCK_DEFERRED_RESUME
	if (mmc_bus_needs_resume(card->host)) {
		mmc_resume_bus(card->host);
		(void)assd_set_blksize(card->host, 512);
	}
#endif
	/*
	 * Check if the inserted card supports assd.
	 */
	if (assd_switch(card->host, SWITCH_CHECK_FUNCTION, 0xF)) {
		printk(KERN_INFO "assd: card does not support assd\n");
		return -ENODEV;
	}
	misc_register(&dev_inserted);
	printk(KERN_INFO "assd: a assd capable card was found\n");
	/*
	 * Some cards require a STOP_TRANSMISSION command, some not.
	 * Sending a STOP_TRANSMISSION command slows down the processing
	 * of a C-APDU if the actual card does not need the
	 * STOP_TRANSMISSION command. Unfortunately if the actual card
	 * needs a STOP_TRANSMISSION command and we do not send the
	 * STOP_TRANSMISSION command, the processing of the C-APDU will
	 * fail. So better start with sending a STOP_TRANSMISSION command
	 * and disable that lateron as soon as we know what kind of card
	 * we deal with.
	 */
	set_bit(ASSD_SEND_STOP, &assd_status);
	sema_init(&assd_lock, 1);
	assd_timeout = (1000 / 16) + 1;
	assd_host = card->host;
	return 0;
}

static void assd_remove(struct mmc_card *card)
{
	pr_debug("assd: assd_remove()\n");
	assd_system.state = 0;
	if (card->host == assd_host) {
		misc_deregister(&dev_inserted);
		printk(KERN_INFO "assd: the assd capable card has been removed\n");
		assd_host = NULL;
	}
}

static int assd_suspend(struct mmc_card *card, pm_message_t state)
{
	pr_debug("assd: assd_suspend()\n");
	if (assd_system.state == 1)
		assd_system.state = 2;
	return 0;
}

static int assd_resume(struct mmc_card *card)
{
	int ret = 0;

	pr_debug("assd: assd_resume()\n");
	if (assd_system.state == 2) {
		if (down_trylock(&assd_lock))
			return -EBUSY;
		ret = assd_enable(assd_host);
		up(&assd_lock);
	}
	return ret;
}

static struct mmc_driver mmc_drv = {
	.drv = {
		.name = "sd_assd",
		},
	.probe   = assd_probe,
	.remove  = assd_remove,
	.suspend = assd_suspend,
	.resume  = assd_resume,
};

static int __init assd_init(void)
{
	pr_debug("assd: assd_init()\n");
	assd_block = kzalloc(512, GFP_KERNEL);
	if (assd_block == NULL)
		return -ENOMEM;
	if (misc_register(&dev)) {
		kfree(assd_block);
		return -EIO;
	}
	if (mmc_register_driver(&mmc_drv)) {
		misc_deregister(&dev);
		kfree(assd_block);
		return -EIO;
	}
	assd_system.state = 0;
	return 0;
};

static void __exit assd_exit(void)
{
	pr_debug("assd: assd_exit()\n");
	assd_system.state = 0xFF;
	mmc_unregister_driver(&mmc_drv);
	misc_deregister(&dev);
	if (assd_host != NULL)
		misc_deregister(&dev_inserted);
	kfree(assd_block);
};

module_init(assd_init);
module_exit(assd_exit);

MODULE_AUTHOR("Giesecke & Devrient GmbH");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Advanced Security SD Extension");
MODULE_VERSION(VERSION);
