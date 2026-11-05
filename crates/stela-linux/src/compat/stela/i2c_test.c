// SPDX-License-Identifier: MIT
/* Linux's I2C core on the fixture's real Runtime task, which its bus lock
 * needs: adapters, transfers with Linux's retries, and unbound clients. */
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <stela/test.h>

void stela_linux_i2c_test(void);

static int results[2];
static unsigned int transfers;

static int transfer(struct i2c_adapter *adapter, struct i2c_msg *msgs, int num)
{
	(void)adapter;
	(void)msgs;
	(void)num;
	return results[transfers++];
}

static u32 functionality(struct i2c_adapter *adapter)
{
	(void)adapter;
	return I2C_FUNC_I2C;
}

static const struct i2c_algorithm algorithm = {.xfer = transfer, .functionality = functionality};

static struct i2c_adapter adapter = {.algo = &algorithm, .retries = 1, .name = "test"};

void stela_linux_i2c_test(void)
{
	assert(!i2c_add_adapter(&adapter) && adapter.timeout == HZ);
	assert(!strcmp(dev_name(&adapter.dev), "i2c-0"));

	/* Arbitration loss retries up to the limit; other errors do not. */
	results[0] = -EAGAIN;
	results[1] = 2;
	assert(i2c_transfer(&adapter, NULL, 2) == 2 && transfers == 2);
	transfers = 0;
	results[0] = results[1] = -EAGAIN;
	assert(i2c_transfer(&adapter, NULL, 1) == -EAGAIN && transfers == 2);
	transfers = 0;
	results[0] = -EIO;
	assert(i2c_transfer(&adapter, NULL, 1) == -EIO && transfers == 1);

	assert(i2c_trylock_bus(&adapter, I2C_LOCK_SEGMENT));
	assert(!i2c_trylock_bus(&adapter, I2C_LOCK_SEGMENT));
	i2c_unlock_bus(&adapter, I2C_LOCK_SEGMENT);

	struct i2c_board_info info = {I2C_BOARD_INFO("sensor", 0x48)};
	struct i2c_client *client = i2c_new_client_device(&adapter, &info);
	assert(!IS_ERR(client) && client->addr == 0x48 && !client->dev.driver);
	assert(!strcmp(client->name, "sensor") && client->adapter == &adapter);
	i2c_unregister_device(client);
	i2c_unregister_device(ERR_PTR(-ENODEV));
	info.addr = 0x80;
	assert(IS_ERR(i2c_new_client_device(&adapter, &info)));

	i2c_del_adapter(&adapter);
}
