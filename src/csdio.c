/*
 * Copyright (c) 2010, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/circ_buf.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/serial_reg.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/idr.h>
#include "csdio_config.h"
/* Char device */
#include <linux/cdev.h>
#include <linux/fs.h>

/* Sdio device */
#include <linux/mmc/card.h>
#include <linux/mmc/core.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>

#include "csdio.h"

#define VERSION "0.5"
#define CSDIO_NUM_OF_SDIO_FUNCTIONS 7
#define CSDIO_DEV_NAME "csdio"
#define TP_DEV_NAME CSDIO_DEV_NAME "f"
#define CSDIO_DEV_PERMISSIONS 0666

#define CSDIO_SDIO_BUFFER_SIZE (64 * 512)

#define CSDIO_MAX_FN 8
#define CSDIO_MAX_CARDS 8
#define CSDIO_MAX_DEVICES (CSDIO_MAX_FN * CSDIO_MAX_CARDS)

static bool g_csdio_initialized = false;

struct csdio_func_t {
  struct sdio_func *m_func;
  struct cdev m_cdev; 
  struct device *m_device;
  struct csdio_card *card;
  struct fasync_struct *m_async_queue;
  char devname[16];
  u32 open_count;
  struct mutex lock;
  int minor;
};

struct csdio_func_pool_t{
  struct csdio_func_t* registered_functions[CSDIO_MAX_FN - 1];
  u8 function_bitmap;
  struct mutex lock;
};

struct csdio_card {
  struct csdio_func_pool_t m_func_pool;
  struct mmc_host *host;
  struct cdev m_cdev;
  struct device *m_device;
  char devname[16];
  void *sdio_buffer;
  int minor;
  struct mutex lock;
  atomic_t nb_functions;
  u8 card_no;
};


struct csdio_t {
  int csdio_major;
  struct ida minor_ida;
  struct ida registered_cards_ida;
  struct class *m_driver_class;
} g_csdio;



 static int csdio_transport_open(struct inode *inode, struct file *filp) {
   int ret = 0;
   struct csdio_func_t *csdio_func; /*  device information */

   struct sdio_func *func;
 
  if (!try_module_get(THIS_MODULE)) {
    pr_err(CSDIO_DEV_NAME ": can't get module refcount when opening csdio function file\n");
    ret =  -ENODEV;
    goto exit;
  }

   csdio_func = container_of(inode->i_cdev, struct csdio_func_t, m_cdev);
   func = csdio_func->m_func;

   mutex_lock(&csdio_func->lock);

   if(csdio_func->open_count == 0){
    sdio_claim_host(func);
    ret = sdio_enable_func(func);
    if (ret) {
      pr_err(CSDIO_DEV_NAME": Cannot enable function %d when closing /dev/%s\n", func->num, csdio_func->devname);
      ret = -EIO;
      module_put(THIS_MODULE); 
      goto release_host;
    }
   }

  csdio_func->open_count++;
  filp->private_data = csdio_func;
  pr_info(CSDIO_DEV_NAME": open csdio function: /dev/%s\n", csdio_func->devname);

release_host:
   sdio_release_host(func);
   mutex_unlock(&csdio_func->lock);
exit:
   return ret;
 }
 
 static int csdio_transport_fasync(int fd, struct file *filp, int mode) {
  struct csdio_func_t *csdio_func;
   pr_info(CSDIO_DEV_NAME ": csdio_transport_fasync: fd=%d, filp=%p, mode=%d\n", fd,
           filp, mode);

    csdio_func = filp->private_data;
    return fasync_helper(fd, filp, mode, &csdio_func->m_async_queue);
 }

 static int csdio_transport_release(struct inode *inode, struct file *filp) {
   int ret = 0;
   struct csdio_func_t *csdio_func; /*  device information */
   struct sdio_func *func;
 
   csdio_func = container_of(inode->i_cdev, struct csdio_func_t, m_cdev);
   func = csdio_func->m_func; 

   mutex_lock(&csdio_func->lock);
    csdio_func->open_count--;
    if(csdio_func->open_count == 0 ){
      sdio_claim_host(func);
      sdio_release_irq(csdio_func->m_func);
      ret = sdio_disable_func(func);
      sdio_release_host(func);

      if (ret) {
        pr_err(CSDIO_DEV_NAME ": disable func %d failed when closing /dev/%s\n", func->num, csdio_func->devname);
        ret = -EIO;
      }
      csdio_transport_fasync(-1, filp, 0);
    }
   mutex_unlock(&csdio_func->lock);
   module_put(THIS_MODULE); 
   pr_info(CSDIO_DEV_NAME": close csdio function %d : /dev/%s\n",  func->num, csdio_func->devname);
   return ret;
 }
 
 /*
  * This handles the interrupt from SDIO.
  */
 static void csdio_sdio_irq(struct sdio_func *func) {
    struct csdio_func_t* csdio_func;
    csdio_func = sdio_get_drvdata(func);

   /*  signal asynchronous readers */
   if (csdio_func->m_async_queue)
     kill_fasync(&csdio_func->m_async_queue, SIGIO, POLL_IN);
 }

// 
// /*
//  * The ioctl() implementation
//  */
// static long int csdio_transport_ioctl(struct file *filp, unsigned int cmd,
//                                       unsigned long arg) {
//   int err = 0;
//   int ret = 0;
//   struct csdio_file_descriptor *descriptor = filp->private_data;
//   struct csdio_func_t *port = descriptor->m_port;
//   struct sdio_func *func = port->m_func;
// 
//   /*  extract the type and number bitfields
//       sanity check: return ENOTTY (inappropriate ioctl) before
//       access_ok()
//   */
//   if ((_IOC_TYPE(cmd) != CSDIO_IOC_MAGIC) || (_IOC_NR(cmd) > CSDIO_IOC_MAXNR)) {
//     pr_err(TP_DEV_NAME "Wrong ioctl command parameters\n");
//     ret = -ENOTTY;
//     goto exit;
//   }
// 
//   /*  the direction is a bitmask, and VERIFY_WRITE catches R/W
//    *  transfers. `Type' is user-oriented, while access_ok is
//       kernel-oriented, so the concept of "read" and "write" is reversed
//   */
//   if (_IOC_DIR(cmd) & _IOC_READ) {
//     err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
//   } else {
//     if (_IOC_DIR(cmd) & _IOC_WRITE) {
//       err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
//     }
//   }
//   if (err) {
//     pr_err(TP_DEV_NAME "Wrong ioctl access direction\n");
//     ret = -EFAULT;
//     goto exit;
//   }
// 
//   switch (cmd) {
//   case CSDIO_IOC_FUNCTION_SET_BLOCK_SIZE: {
//     unsigned block_size;
// 
//     block_size = (unsigned) arg;
// 
//     pr_info(TP_DEV_NAME "%d:SET_BLOCK_SIZE=%d\n", func->num, block_size);
//     sdio_claim_host(func);
//     ret = sdio_set_block_size(func, block_size);
//     sdio_release_host(func);
//     if (!ret) {
//       port->m_block_size = block_size;
//     } else {
//       pr_err(TP_DEV_NAME "%d:SET_BLOCK_SIZE set block"
//                          " size to %d failed (%d)\n",
//              func->num, block_size, ret);
//       ret = -ENOTTY;
//       break;
//     }
//   } break;
//   case CSDIO_IOC_CMD52: {
//     struct csdio_cmd52_ctrl_t cmd52ctrl;
//     if (copy_from_user(&cmd52ctrl, (const unsigned char __user *)arg,
//                        sizeof(cmd52ctrl))){
//       pr_err(TP_DEV_NAME "%d:IOC_CMD52 get"
//                          " from user space failed\n",
//              func->num);
//       ret = -EFAULT;
//       break;
//     }
//     sdio_claim_host(func);
//     if (cmd52ctrl.m_write)
//       sdio_writeb(func, cmd52ctrl.m_data, cmd52ctrl.m_address, &ret);
//     else
//       cmd52ctrl.m_data = sdio_readb(func, cmd52ctrl.m_address, &ret);
// 
//     sdio_release_host(func);
// 
//     if (ret){
//       pr_err(TP_DEV_NAME "%d:IOC_CMD52 failed (%d)\n", func->num,
//              ret);
//       break;
//       }
// 
//     if (copy_to_user((unsigned char __user *)arg, &cmd52ctrl,
//                      sizeof(cmd52ctrl))) {
//       pr_err(TP_DEV_NAME "%d:IOC_CMD52 put data"
//                          " to user space failed\n",
//              func->num);
//       ret = -EFAULT;
//     }
// 
//   } break;
//   case CSDIO_IOC_CMD53: {
//     struct csdio_cmd53_ctrl_t csdio_cmd53_ctrl;
//     unsigned long uncopied_bytes;
//     size_t byte_count;
// 
//     if (copy_from_user(&csdio_cmd53_ctrl, (const char __user *)arg,
//                        sizeof(csdio_cmd53_ctrl))) {
//       ret = -EFAULT;
//       pr_err(TP_DEV_NAME "%d:"
//                          "Get data from user space failed\n",
//              func->num);
//       break;
//     }
//     if (csdio_cmd53_ctrl.m_block_mode) {
//       byte_count = port->m_block_size * csdio_cmd53_ctrl.m_byte_block_count;
//     }
//     else{
//         byte_count = csdio_cmd53_ctrl.m_byte_block_count;
//     }
// 
//     if(csdio_cmd53_ctrl.m_write){
//         if( (uncopied_bytes = copy_from_user(g_sdio_buffer, csdio_cmd53_ctrl.m_data, byte_count))){
//            pr_err(TP_DEV_NAME "F%d:"
//                                "CMD53 could not copy remaining %lu bytes of CMD53 data !\n", func->num, uncopied_bytes);
//             ret = -EFAULT;
//         }
//     }
// 
//     sdio_claim_host(func);
// 
//     if (csdio_cmd53_ctrl.m_op_code) {
//       if(csdio_cmd53_ctrl.m_write){
//           ret = sdio_memcpy_toio(func, csdio_cmd53_ctrl.m_address, g_sdio_buffer, byte_count);
//       }
//         else{
//           ret = sdio_memcpy_fromio(func, g_sdio_buffer, csdio_cmd53_ctrl.m_address, byte_count);
//         }
//     } else {
//       if (csdio_cmd53_ctrl.m_write) {
//         ret = sdio_writesb(func, csdio_cmd53_ctrl.m_address,
//                      g_sdio_buffer, byte_count);
//       }
//       else{
//         ret = sdio_readsb(func, g_sdio_buffer, csdio_cmd53_ctrl.m_address,
//                      byte_count);
//         }
//     }
//     if(ret){
//    pr_err(TP_DEV_NAME "F%d:"
//                          "CMD53 failed with error %d !\n",
//              func->num, ret);
// 
//       }
// 
//     sdio_release_host(func);
//   
//    if(!csdio_cmd53_ctrl.m_write){
//         if( (uncopied_bytes = copy_to_user(csdio_cmd53_ctrl.m_data, g_sdio_buffer, byte_count)) ){
//          pr_err(TP_DEV_NAME "F%d:"
//                                "Could not copy remaining %lu bytes of CMD53 Data!\n", func->num, uncopied_bytes);
//           ret = -EFAULT;
//         }
//     }   
// 
//   } break;
//   case CSDIO_IOC_CONNECT_ISR: {
// 
//     sdio_claim_host(func);
//     ret = sdio_claim_irq(func, csdio_sdio_irq);
//     sdio_release_host(func);
//     if (ret) {
//       pr_err(CSDIO_DEV_NAME " SDIO_CONNECT_ISR"
//                             " claim irq failed(%d)\n",
//              ret);
//     } else {
//       /* update current irq mask for disable/enable */
//       g_csdio.m_current_irq_mask |= (1 << func->num);
//     }
//   } break;
//   case CSDIO_IOC_DISCONNECT_ISR: {
//     pr_info(CSDIO_DEV_NAME " SDIO_DISCONNECT_ISR func=%d\n", func->num);
//     sdio_claim_host(func);
//     sdio_release_irq(func);
//     sdio_release_host(func);
//     /* update current irq mask for disable/enable */
//     g_csdio.m_current_irq_mask &= ~(1 << func->num);
//   } break;
//   default: /*  redundant, as cmd was checked against MAXNR */
//     pr_warn(TP_DEV_NAME "%d: Redundant IOCTL, cmd %d\n", func->num, cmd);
//     ret = -ENOTTY;
//   }
// exit:
//   return ret;
// }
// 
 static const struct file_operations csdio_transport_fops = {
     .owner = THIS_MODULE,
     .unlocked_ioctl = NULL, //csdio_transport_ioctl,
     .open = csdio_transport_open,
     .release = csdio_transport_release,
     .fasync = csdio_transport_fasync
 };
// 
// 
// static void csdio_transport_cleanup(struct csdio_func_t *port) {
//   int devno = MKDEV(csdio_major, csdio_minor + port->m_func->num);
//   pr_err(CSDIO_DEV_NAME " csdio major %d  csdio minor %d drv_class %p\n",csdio_major, csdio_minor + port->m_func->num, g_csdio.m_driver_class);
//   device_destroy(g_csdio.m_driver_class, devno);
//   port->m_device = NULL;
//   cdev_del(&port->m_cdev);
// }
// #if defined(CONFIG_DEVTMPFS)
// static inline int csdio_cdev_update_permissions(const char *devname,
//                                                 int dev_minor) {
//   return 0;
// }
// #else
// static int csdio_cdev_update_permissions(const char *devname, int dev_minor) {
//   int ret = 0;
//   mm_segment_t fs;
//   struct file *file;
//   struct inode *inode;
//   struct iattr newattrs;
//   int mode = CSDIO_DEV_PERMISSIONS;
//   char dev_file[64];
// 
//   fs = get_fs();
//   set_fs(get_ds());
// 
//   snprintf(dev_file, sizeof(dev_file), "/dev/%s%d", devname, dev_minor);
//   file = filp_open(dev_file, O_RDWR, 0);
//   if (IS_ERR(file)) {
//     ret = -EFAULT;
//     goto exit;
//   }
// 
//   inode = file->f_path.dentry->d_inode;
// 
//   mutex_lock(&inode->i_mutex);
//   newattrs.ia_mode = (mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO);
//   newattrs.ia_valid = ATTR_MODE | ATTR_CTIME;
//   ret = notify_change(file->f_path.dentry, &newattrs);
//   mutex_unlock(&inode->i_mutex);
// 
//   filp_close(file, NULL);
// 
// exit:
//   set_fs(fs);
//   return ret;
// }
// #endif

static void csdio_cdev_deinit(struct cdev *char_dev,
                              int dev_minor,
                              const char *devname)
{
    dev_t devno;

    if (!char_dev)
        return;

    devno = MKDEV(g_csdio.csdio_major, dev_minor);

    /* Remove the device node if it was created */
    device_destroy(g_csdio.m_driver_class, devno);
    
    /* Remove the char device */
    cdev_del(char_dev);
}

 static int csdio_cdev_init(struct cdev *char_dev,
                                        struct device *device,
                                       const struct file_operations *file_op,
                                       int dev_minor, const char *devname,
                                       struct device *parent) {
   int ret = 0;
   int devno = MKDEV(g_csdio.csdio_major, dev_minor);
 
   cdev_init(char_dev, file_op);
   char_dev->owner = THIS_MODULE;
   ret = cdev_add(char_dev, devno, 1);
 
   if (ret) {
     pr_err(CSDIO_DEV_NAME ": error %d adding %s with minor %d\n", ret, devname,
             dev_minor);
     goto exit;
   }
 
   device = device_create(g_csdio.m_driver_class, parent, devno, NULL,
                              devname);
   if (!device) {
     pr_err(CSDIO_DEV_NAME ": can't create device node %s%d\n", devname, dev_minor);
     goto cleanup;
   }
 
   // if (csdio_cdev_update_permissions(devname, dev_minor)) {
   //   pr_warn("%s%d: Unable to update access permissions of the"
   //           " '/dev/%s%d'\n",
   //           devname, dev_minor, devname, dev_minor);
   // }
 
   pr_info(CSDIO_DEV_NAME ": device node '/dev/%s' created successfully\n", devname);

   goto exit;
 cleanup:
   cdev_del(char_dev);
 exit:
   return ret;
 }

// 
// 
// static int set_vdd_helper(int value) {
//   struct mmc_ios *ios = NULL;
// 
//   if (NULL == g_csdio.m_host) {
//     pr_err("%s0: Set VDD, no MMC host assigned\n", CSDIO_DEV_NAME);
//     return -ENXIO;
//   }
// 
//   sdio_claim_host(get_active_func());
//   ios = &g_csdio.m_host->ios;
//   ios->vdd = value;
//   g_csdio.m_host->ops->set_ios(g_csdio.m_host, ios);
//   sdio_release_host(get_active_func());
//   return 0;
// }
// 
// /*
//  * The ioctl() implementation for control device
//  */
// static long int csdio_ctrl_ioctl(struct file *filp, unsigned int cmd,
//                                  unsigned long arg) {
//   int err = 0;
//   int ret = 0;
// 
//   pr_info("CSDIO ctrl ioctl.\n");
// 
//   /*  extract the type and number bitfields
//       sanity check: return ENOTTY (inappropriate ioctl) before
//       access_ok()
//   */
//   if ((_IOC_TYPE(cmd) != CSDIO_IOC_MAGIC) || (_IOC_NR(cmd) > CSDIO_IOC_MAXNR)) {
//     pr_err(CSDIO_DEV_NAME "Wrong ioctl command parameters\n");
//     ret = -ENOTTY;
//     goto exit;
//   }
// 
//   /*  the direction is a bitmask, and VERIFY_WRITE catches R/W
//     transfers. `Type' is user-oriented, while access_ok is
//     kernel-oriented, so the concept of "read" and "write" is reversed
//     */
//   if (_IOC_DIR(cmd) & _IOC_READ) {
//     err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
//   } else {
//     if (_IOC_DIR(cmd) & _IOC_WRITE)
//       err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
//   }
//   if (err) {
//     pr_err(CSDIO_DEV_NAME "Wrong ioctl access direction\n");
//     ret = -EFAULT;
//     goto exit;
//   }
// 
//   switch (cmd) {
//   case CSDIO_IOC_ENABLE_HIGHSPEED_MODE:
//     pr_info(CSDIO_DEV_NAME " ENABLE_HIGHSPEED_MODE\n");
//     break;
//   case CSDIO_IOC_SET_DATA_TRANSFER_CLOCKS: {
//     struct mmc_host *host = g_csdio.m_host;
//     struct mmc_ios *ios = NULL;
// 
//     if (NULL == host) {
//       pr_err("%s0: "
//              "CSDIO_IOC_SET_DATA_TRANSFER_CLOCKS,"
//              " no MMC host assigned\n",
//              CSDIO_DEV_NAME);
//       ret = -EFAULT;
//       goto exit;
//     }
//     ios = &host->ios;
// 
//     sdio_claim_host(get_active_func());
//     ret = get_user(host->ios.clock, (unsigned int __user *)arg);
//     if (ret) {
//       pr_err(CSDIO_DEV_NAME " get data from user space failed\n");
//     } else {
//       pr_err(CSDIO_DEV_NAME "SET_DATA_TRANSFER_CLOCKS(%d-%d)(%d)\n",
//              host->f_min, host->f_max, host->ios.clock);
//       host->ops->set_ios(host, ios);
//     }
//     sdio_release_host(get_active_func());
//   } break;
//   case CSDIO_IOC_SET_VDD: {
//     unsigned int vdd = 0;
// 
//     ret = get_user(vdd, (unsigned int __user *)arg);
//     if (ret) {
//       pr_err("%s0: CSDIO_IOC_SET_VDD,"
//              " get data from user space failed\n",
//              CSDIO_DEV_NAME);
//       goto exit;
//     }
//     pr_info(CSDIO_DEV_NAME " CSDIO_IOC_SET_VDD - %d\n", vdd);
// 
//     ret = set_vdd_helper(vdd);
//     if (ret)
//       goto exit;
//   } break;
//   case CSDIO_IOC_GET_VDD: {
//     if (NULL == g_csdio.m_host) {
//       pr_err("%s0: CSDIO_IOC_GET_VDD,"
//              " no MMC host assigned\n",
//              CSDIO_DEV_NAME);
//       ret = -EFAULT;
//       goto exit;
//     }
//     ret = put_user(g_csdio.m_host->ios.vdd, (unsigned short __user *)arg);
//     if (ret) {
//       pr_err("%s0: CSDIO_IOC_GET_VDD, put data"
//              " to user space failed\n",
//              CSDIO_DEV_NAME);
//       goto exit;
//     }
//     break;
//   }
//   case CSDIO_IOC_CMD52: {
//     struct sdio_func *func = get_active_func();
//     struct csdio_cmd52_ctrl_t cmd52ctrl;
//     
// 
//       pr_err(TP_DEV_NAME "func addr: %p\n", func);
//       pr_err(TP_DEV_NAME "func num: %d\n", func->num);
// 
//     if (copy_from_user(&cmd52ctrl, (const unsigned char __user *)arg,
//                        sizeof(cmd52ctrl))) {
//       pr_err(TP_DEV_NAME "%s0:IOC_ F0 CMD52 get data"
//                          " from user space failed\n",
//              CSDIO_DEV_NAME);
//       ret = -ENOTTY;
//       break;
//     }
//       pr_err(TP_DEV_NAME "write: 0x%x\n", cmd52ctrl.m_write);
//       pr_err(TP_DEV_NAME "addr: 0x%x\n", cmd52ctrl.m_address);
//       pr_err(TP_DEV_NAME "data: 0x%x\n", cmd52ctrl.m_data);
// 
//     sdio_claim_host(func);
//     if (cmd52ctrl.m_write)
//       sdio_f0_writeb(func, cmd52ctrl.m_data, cmd52ctrl.m_address, &ret);
//     else
//       cmd52ctrl.m_data = sdio_f0_readb(func, cmd52ctrl.m_address, &ret);
// 
//     sdio_release_host(func);
// 
//     if (ret)
//       pr_err(TP_DEV_NAME "%s0:IOC_CMD52 failed (%d)\n", CSDIO_DEV_NAME,
//              ret);
// 
//     if (copy_to_user((unsigned char __user *)arg, &cmd52ctrl,
//                      sizeof(cmd52ctrl))) {
//       pr_err(TP_DEV_NAME "%s0:IOC_CMD52 put data"
//                          " to user space failed\n",
//              CSDIO_DEV_NAME);
//       ret = -ENOTTY;
//     }
//   } break;
//   default: /*  redundant, as cmd was checked against MAXNR */
//     pr_warn(CSDIO_DEV_NAME " Redundant IOCTL, cmd %d\n", cmd);
//     ret = -ENOTTY;
//   }
// exit:
//   return ret;
// }
// 
 
 /*
  * Open and close
  */
 static int csdio_ctrl_open(struct inode *inode, struct file *filp) {
   int ret = 0;
   struct csdio_card *csdio_card; /*  device information */
 

  if (!try_module_get(THIS_MODULE)) {
      pr_err(CSDIO_DEV_NAME ": can't get module refcount when opening sdio card file\n");
      ret =  -ENODEV;
    goto exit;
  }

  csdio_card = container_of(inode->i_cdev, struct csdio_card, m_cdev);
  pr_info(CSDIO_DEV_NAME ": open file %s", csdio_card->devname);
  filp->private_data = csdio_card; /*  for other methods */
exit:
   return ret;
 }
 
 static int csdio_ctrl_release(struct inode *inode, struct file *filp) {
   struct csdio_card *csdio_card; /*  device information */
  csdio_card = container_of(inode->i_cdev, struct csdio_card, m_cdev);

    pr_info(CSDIO_DEV_NAME ": close file %s", csdio_card->devname);
   module_put(THIS_MODULE); 
   return 0;
 }
 
 static const struct file_operations csdio_ctrl_fops = {
     .owner = THIS_MODULE,
     .unlocked_ioctl = NULL, //csdio_ctrl_ioctl,
     .open = csdio_ctrl_open,
     .release = csdio_ctrl_release,
 };

 static void csdio_func_dealloc(struct csdio_func_t *csdio_func){
    csdio_cdev_deinit(&csdio_func->m_cdev, csdio_func->minor, CSDIO_DEV_NAME);
    atomic_dec(&csdio_func->card->nb_functions);
    kfree(csdio_func);
 }

static void csdio_card_dealloc(struct csdio_card *csdio_card)
{
    csdio_cdev_deinit(&csdio_card->m_cdev, csdio_card->minor, CSDIO_DEV_NAME);
    ida_free(&g_csdio.registered_cards_ida,csdio_card->card_no);
    kfree(csdio_card->sdio_buffer);
    kfree(csdio_card);
}

static int csdio_func_alloc(struct csdio_func_t **csdio_func,struct csdio_card* csdio_card, struct sdio_func *func, int minor){
  int ret = 0;

  struct csdio_func_t *new_csdio_func;
  new_csdio_func = kzalloc(sizeof(struct csdio_func_t), GFP_KERNEL);
  if (!new_csdio_func) {
    pr_err(CSDIO_DEV_NAME": can't allocate memory for csdio function: %d\n", func->num);
    ret = -ENOMEM;
    goto exit;
  }

  /* initialize SDIO side */
  new_csdio_func->m_func = func;
  sdio_set_drvdata(func, new_csdio_func);

  scnprintf(new_csdio_func->devname, sizeof(new_csdio_func->devname), "%s%d%s%d", CSDIO_DEV_NAME, csdio_card->card_no, "f", func->num);

  if ((ret = csdio_cdev_init(&new_csdio_func->m_cdev, new_csdio_func->m_device, &csdio_transport_fops,
                                minor, new_csdio_func->devname,
                                &func->dev))){

    goto deallocate_csdio_func;
  }

  new_csdio_func->minor = minor;
  new_csdio_func->m_async_queue = NULL;
  new_csdio_func->open_count = 0;
  new_csdio_func->card = csdio_card;

  mutex_init(&new_csdio_func->lock);
  atomic_inc(&new_csdio_func->card->nb_functions);

  pr_info(CSDIO_DEV_NAME": new csdio function: %s\n", new_csdio_func->devname);
  *csdio_func = new_csdio_func;
  goto exit;

  deallocate_csdio_func:
    kfree(new_csdio_func);
  exit:
    return ret;
}

static int csdio_card_alloc(struct csdio_card **csdio_card, struct mmc_host *host, int minor, int card_no){
  int ret;

  struct csdio_card* new_csdio_card = kzalloc(sizeof(struct csdio_card), GFP_KERNEL);

  if(!new_csdio_card){
    pr_err(CSDIO_DEV_NAME": can't allocate memory for %s%d\n", CSDIO_DEV_NAME, card_no);
    ret = -ENOMEM;
    goto exit;
  }

  scnprintf(new_csdio_card->devname, sizeof(new_csdio_card->devname), "%s%d", CSDIO_DEV_NAME, card_no);

  new_csdio_card->sdio_buffer = kmalloc(CSDIO_SDIO_BUFFER_SIZE, GFP_KERNEL);

  if(!new_csdio_card->sdio_buffer){
    pr_err(CSDIO_DEV_NAME": can't allocate rx buffer for csdio card: %s%d\n", CSDIO_DEV_NAME, new_csdio_card->card_no);
    ret = -ENOMEM;
    goto free_csdio_card;
  }

   if((ret = csdio_cdev_init(&new_csdio_card->m_cdev, new_csdio_card->m_device, &csdio_ctrl_fops,
                                            minor, new_csdio_card->devname, NULL))){
    pr_err(CSDIO_DEV_NAME ": can't initialize csdio card cdev: %s%d\n", CSDIO_DEV_NAME, new_csdio_card->card_no);
    ret = -ENOENT;
    goto free_sdio_buffer;
  }

  mutex_init(&new_csdio_card->m_func_pool.lock);
  new_csdio_card->m_func_pool.function_bitmap = 0;

  new_csdio_card->host = host;
  new_csdio_card->minor = minor;
  new_csdio_card->card_no = card_no;
  atomic_set(&new_csdio_card->nb_functions, 0);
  mutex_init(&new_csdio_card->lock);

  pr_info(CSDIO_DEV_NAME": new csdio card: %s%d\n", CSDIO_DEV_NAME, new_csdio_card->card_no);
  *csdio_card = new_csdio_card;

  goto exit;

  free_sdio_buffer:
    kfree(new_csdio_card->sdio_buffer);
  free_csdio_card:
    kfree(new_csdio_card);
  exit:
    return ret;
}

// Only to be called from csdio_probe()
static struct csdio_card* get_csdio_card_from_mmc_card(struct mmc_card* mmc_card){
  struct sdio_func* sdio_func;
  struct csdio_func_t* csdio_func;
  int loaded_functions;

  pr_info(CSDIO_DEV_NAME": nb func %d\n", mmc_card->sdio_funcs);

  loaded_functions = atomic_read(&mmc_card->sdio_funcs_probed) - 1;
  for(int index = 0; index <  loaded_functions; index++){
    sdio_func = mmc_card->sdio_func[index];
    if(sdio_func){
      csdio_func = sdio_get_drvdata(sdio_func);
      return csdio_func->card;
    }
  }
  return NULL;
}

static int csdio_probe(struct sdio_func *func,
                       const struct sdio_device_id *id) {
  struct csdio_func_t *csdio_func;
  struct mmc_host *mmc_host;
  struct csdio_card* csdio_card;
  struct csdio_func_pool_t* func_pool;
  int new_csdio_card_minor;
  int new_csdio_card_id;
  int new_csdio_func_minor;
  int ret = 0;
  bool new_card;

  csdio_card = get_csdio_card_from_mmc_card(func->card);

  if(csdio_card){
    new_card = false; 
  }
  else{
    new_card = true;
    new_csdio_card_minor = ida_simple_get(&g_csdio.minor_ida,
                                            0, CSDIO_MAX_DEVICES, GFP_KERNEL);
    new_csdio_card_id = ida_simple_get(&g_csdio.registered_cards_ida,
                                            0, CSDIO_MAX_CARDS, GFP_KERNEL);
    if ((ret = csdio_card_alloc(&csdio_card, mmc_host, new_csdio_card_minor, new_csdio_card_id))){
      goto exit;
    }
  }

  // Allow RW operations on on any field of the CCR region 
  func->card->quirks |= MMC_QUIRK_LENIENT_FN0;


  new_csdio_func_minor = ida_simple_get(&g_csdio.minor_ida,
                                        0, CSDIO_MAX_DEVICES, GFP_KERNEL);

  if ((ret = csdio_func_alloc(&csdio_func, csdio_card, func, new_csdio_func_minor))){
    goto dealloc_csdio_card;
  }

  func_pool = &csdio_card->m_func_pool;

  mutex_lock(&func_pool->lock);
  func_pool->registered_functions[func->num - 1] = csdio_func;
  func_pool->function_bitmap |= 1 << (func->num - 1);
  mutex_unlock(&func_pool->lock);
  goto exit;

  dealloc_csdio_card:
    if(new_card) csdio_card_dealloc(csdio_card);
  exit:
    return ret;
}

static void csdio_remove(struct sdio_func *func) {
  struct csdio_card* csdio_card;
  struct csdio_func_t *csdio_func = sdio_get_drvdata(func);
  u32 nb_functions;
  
  csdio_card = csdio_func->card;
  csdio_func_dealloc(csdio_func);

   nb_functions = atomic_read(&csdio_card->nb_functions);
  if(nb_functions == 0){
    csdio_card_dealloc(csdio_card);
  }
}

static struct sdio_device_id csdio_ids[] = {
  {SDIO_DEVICE(0x024c, 0xb852), .class = SDIO_CLASS_WLAN},
  {/* end: all zeroes */},
};

//static struct sdio_device_id csdio_ids[] = {
//    { SDIO_DEVICE(CONFIG_CSDIO_VENDOR_ID, CONFIG_CSDIO_DEVICE_ID) },
//    { /* end */ }
//};

MODULE_DEVICE_TABLE(sdio, csdio_ids);

static struct sdio_driver csdio_driver = {
    .probe = csdio_probe,
    .remove = csdio_remove,
    .name = "csdio",
    .id_table = csdio_ids,
};

static void __exit csdio_exit(void) {
  dev_t devno;
  pr_info(CSDIO_DEV_NAME": Exit driver\n");
    devno = MKDEV(g_csdio.csdio_major, 0);
   sdio_unregister_driver(&csdio_driver);
   class_destroy(g_csdio.m_driver_class);
   unregister_chrdev_region(devno, CSDIO_MAX_DEVICES);
}

//static char *csdio_devnode( struct device *dev, umode_t *mode) {
//  if(mode) *mode = CSDIO_DEV_PERMISSIONS;
//  return kasprintf(GFP_KERNEL, "%s", dev_name(dev));;
//}

static int __init csdio_init(void) {
    int ret = 0;
    dev_t devno = 0;
    if (g_csdio_initialized) {
      return -EALREADY;
   }
    pr_info(CSDIO_DEV_NAME ": init CSDIO driver module\n");
  
    ret = alloc_chrdev_region(&devno, 0, CSDIO_MAX_DEVICES,
                              CSDIO_DEV_NAME);

    if (ret < 0) {
      pr_err(CSDIO_DEV_NAME ": can't allocate major\n");
      goto exit;
    }

    g_csdio.csdio_major = MAJOR(devno);
    ida_init(&g_csdio.minor_ida);
    ida_init(&g_csdio.registered_cards_ida);

    pr_info(CSDIO_DEV_NAME": char driver major number is %d\n", g_csdio.csdio_major);

    /*  prepare create /dev/... instance */
    g_csdio.m_driver_class = class_create(THIS_MODULE, CSDIO_DEV_NAME);
    
  if (IS_ERR(g_csdio.m_driver_class)) {
    ret = -ENOMEM;
    pr_err(CSDIO_DEV_NAME": class_create failed\n");
    goto unregister_region;
  }

  ret = sdio_register_driver(&csdio_driver);
  if (ret) {
      pr_err(CSDIO_DEV_NAME ": Unable to register as SDIO driver\n");
    goto destroy_class;
  }

  g_csdio_initialized = true;
  goto exit;

 destroy_class:
   class_destroy(g_csdio.m_driver_class);
unregister_region:
  unregister_chrdev_region(devno, CSDIO_MAX_DEVICES);
exit:
  return ret;
}

module_init(csdio_init);
module_exit(csdio_exit);

MODULE_AUTHOR("The Linux Foundation");
MODULE_DESCRIPTION("CSDIO device driver version " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL v2");
