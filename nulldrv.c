#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
  
static int __init ofcd_init(void) /* Constructor */
{
	return 0;
}
 
static void __exit ofcd_exit(void) /* Destructor */
{
}
 
module_init(ofcd_init);
module_exit(ofcd_exit);
