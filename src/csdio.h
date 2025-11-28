#ifndef CSDIO_H
#define CSDIO_H

#include <linux/ioctl.h>

struct csdio_cmd53_ctrl_t {
	unsigned long    m_write;
	unsigned long    m_block_mode;   /* data tran. byte(0)/block(1) mode */
	unsigned long    m_op_code;      /* address auto increment flag */
	unsigned long    m_address;
  unsigned long    m_byte_block_count;
  unsigned char*    m_data;
} __attribute__ ((packed));

struct csdio_cmd52_ctrl_t {
	unsigned long    m_write;
	unsigned long    m_address;
	unsigned long    m_data;
} __attribute__ ((packed));

#define CSDIO_IOC_MAGIC  'm'

#define CSDIO_IOC_ENABLE_HIGHSPEED_MODE      _IO(CSDIO_IOC_MAGIC, 0)
#define CSDIO_IOC_SET_DATA_TRANSFER_CLOCKS   _IO(CSDIO_IOC_MAGIC, 1)
#define CSDIO_IOC_SET_OP_CODE                _IO(CSDIO_IOC_MAGIC, 2)
#define CSDIO_IOC_FUNCTION_SET_BLOCK_SIZE    _IOW(CSDIO_IOC_MAGIC, 3, unsigned)
#define CSDIO_IOC_SET_BLOCK_MODE             _IO(CSDIO_IOC_MAGIC, 4)
#define CSDIO_IOC_CONNECT_ISR                _IO(CSDIO_IOC_MAGIC, 5)
#define CSDIO_IOC_DISCONNECT_ISR             _IO(CSDIO_IOC_MAGIC, 6)
#define CSDIO_IOC_CMD52                      _IOWR(CSDIO_IOC_MAGIC, 7, struct csdio_cmd52_ctrl_t)
#define CSDIO_IOC_CMD53                      _IOWR(CSDIO_IOC_MAGIC, 8, struct csdio_cmd53_ctrl_t)
#define CSDIO_IOC_ENABLE_ISR                 _IO(CSDIO_IOC_MAGIC, 9)
#define CSDIO_IOC_DISABLE_ISR                _IO(CSDIO_IOC_MAGIC, 10)
#define CSDIO_IOC_SET_VDD                    _IO(CSDIO_IOC_MAGIC, 11)
#define CSDIO_IOC_GET_VDD                    _IO(CSDIO_IOC_MAGIC, 12)

#define CSDIO_IOC_MAXNR   12


#endif
