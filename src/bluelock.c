#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "dbus/dbus.h"
#include "mbedtls/aes.h"
#include "bluelock.h"



#define DEBUG(fmt, arg...)  do{if(bluelock_debug)printf("--BlueLock-- " fmt "\n", ##arg);}while(0)
#define ERROR(fmt, arg...)  printf("--BlueLock-- %s(): " fmt "\n", __FUNCTION__, ##arg)


typedef struct {
    DBusConnection *conn;
    u32 hci;
    char hci_obj[16];
    char dev_obj[48];
    char gatt_w_obj[72];
    char gatt_r_obj[72];
}BL_ctx_t;

typedef struct {
    u8 prefix;
    u8 cmd_id;
    u8 data[16];
    u8 crc16_l;
    u8 crc16_h;
}BL_cmd_t;


int bluelock_debug = 1;




void strupr(char *str)
{
    if (NULL == str)
        return;
    for ( ; 0 != *str; str++)
        *str = toupper(*str);
}
void strlwr(char *str)
{
    if (NULL == str)
        return;
    for ( ; 0 != *str; str++)
        *str = tolower(*str);
}


u16 get_crc16(const u8 *data, int length)
{
    u16 value1 = 0;
    u16 value2 = 0;
    u16 value3 = 0xFFFF;
    int i = 0;

    for (i = 0; i < length; i++)
    {
        if (0 == (i % 8))
            value1 = (*data++) << 8;
        value2 = value3 ^ value1;
        value3 = value3 << 1;
        value1 = value1 << 1;
        if(value2 & 0x8000)
            value3 = value3 ^ 0x1021;
    }
    return value3;
}


void aes_enc(u8 out[16], u8 in[16], u8 key[16])
{
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
}
void aes_dec(u8 out[16], u8 in[16], u8 key[16])
{
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, in, out);
}


//返回 /org/bluez/hcix
static int get_hci_obj_str(u32 hci, char *buf, unsigned int buf_len)
{
    int len;

    len = snprintf(buf, buf_len, "/org/bluez/hci%u", hci);
    if (buf_len <= len)
    {
        ERROR("obj len(%d) exceeds buf len(%u) !", len, buf_len);
        return -1;
    }
    return len;
}
//返回 /org/bluez/hcix/dev_xx_xx_xx_xx_xx_xx
static int get_dev_obj_str(u32 hci, const char *mac, char *buf, unsigned int buf_len)
{
    int len;
    int i;

    len = snprintf(buf, buf_len, "/org/bluez/hci%u/dev_%s", hci, mac);
    if (buf_len <= len)
    {
        ERROR("obj len(%d) exceeds buf len(%u) !", len, buf_len);
        return -1;
    }
    for (i = 0; i < len; i++)
    {
        if ((':' == buf[i]) || ('-' == buf[i]) || ('.' == buf[i]) || (',' == buf[i]))
            buf[i] = '_';
    }
    strupr(buf + 20);
    return len;
}




DBusMessage* method_call_reply(DBusConnection *conn, DBusMessage *msg)
{
    DBusPendingCall *pending;
    DBusMessage *msg_recv;


    if (NULL == conn || NULL == msg)
        return NULL;

    if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
    {
        ERROR("dbus_connection_send_with_reply failed !\n");
        return NULL;
    }
    if (NULL == pending)
    {
        ERROR("pending is NULL !\n");
        return NULL;
    }
    dbus_connection_flush(conn);
    //dbus_message_unref(msg);
    dbus_pending_call_block(pending);
    msg_recv = dbus_pending_call_steal_reply(pending);
    if (NULL == msg_recv)
    {
        ERROR("reply is NULL !\n");
        dbus_pending_call_unref(pending);
        return NULL;
    }
    dbus_pending_call_unref(pending);
    return msg_recv;
}


DBusMessage* get_property(DBusConnection *conn,
                          const char *dest,
                          const char *obj,
                          const char *iface,
                          const char *property)
{
    DBusMessage *msg_send;
    DBusMessage *msg_recv;
    DBusMessageIter args;


    if (NULL == conn || NULL == dest || NULL == obj || NULL == iface || NULL == property)
        return NULL;

    msg_send = dbus_message_new_method_call(dest, obj,
                                            "org.freedesktop.DBus.Properties",
                                            "Get");
    if (NULL == msg_send)
        return NULL;
    dbus_message_iter_init_append(msg_send, &args);
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &iface))
        return NULL;
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &property))
        return NULL;
    msg_recv = method_call_reply(conn, msg_send);
    dbus_message_unref(msg_send);

    return msg_recv;
}


int has_object(DBusConnection *conn, const char *dest, const char *obj)
{
    DBusMessage *msg_send;
    DBusMessage *msg_recv;
    DBusMessageIter args;
    DBusMessageIter args_a;
    DBusMessageIter args_ae;
    char *err_str;
    char *_obj;
    int has = 0;


    if (NULL == conn || NULL == dest || NULL == obj)
        return -1;


    msg_send = dbus_message_new_method_call(dest, "/",
                                            "org.freedesktop.DBus.ObjectManager",
                                            "GetManagedObjects");
    if (NULL == msg_send)
        return 0;
    msg_recv = method_call_reply(conn, msg_send);
    dbus_message_unref(msg_send);
    if (NULL == msg_recv)
        return 0;

    if (!dbus_message_iter_init(msg_recv, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        dbus_message_iter_get_basic(&args, &err_str);
        ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_a);
    for (;;)
    {
        if (DBUS_TYPE_DICT_ENTRY != dbus_message_iter_get_arg_type(&args_a))
            goto EXIT;
        dbus_message_iter_recurse(&args_a, &args_ae);
        if (DBUS_TYPE_OBJECT_PATH != dbus_message_iter_get_arg_type(&args_ae))
            goto EXIT;
        dbus_message_iter_get_basic(&args_ae, &_obj);
        if (0 == strcmp(obj, _obj))
        {
            has = 1;
            goto EXIT;
        }
        if (!dbus_message_iter_next(&args_a))
            goto EXIT;
    }

EXIT:
    dbus_message_unref(msg_recv);
    return has;
}








int _is_powered(DBusConnection *conn, const char *hci_obj)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    dbus_bool_t v = 0;


    msg = get_property(conn, "org.bluez",
                             hci_obj,
                             "org.bluez.Adapter1",
                             "Powered");
    if (NULL == msg)
    {
        ERROR("failed to get 'Powered' \"%s\" !\n", hci_obj);
        return 0;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &v);

EXIT:
    dbus_message_unref(msg);
    return !!v;
}
int set_power(DBusConnection *conn, const char *hci_obj, int on)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_a;
    char *str;
    dbus_bool_t v;
    int i;
    int ret = -1;


    on = !!on;
    v = on;
    if (on)
        DEBUG("power on");
    else
        DEBUG("power off");

    if ((NULL == conn) || (NULL == hci_obj))
        return -1;

    if (!has_object(conn, "org.bluez", hci_obj))
    {
        ERROR("hci obj not exist \"%s\" !", hci_obj);
        return -1;
    }
    if (_is_powered(conn, hci_obj) == on)
        return 0;

    msg = dbus_message_new_method_call("org.bluez",
                                       hci_obj,
                                       "org.freedesktop.DBus.Properties",
                                       "Set");
    if (NULL == msg)
        return -1;

    dbus_message_iter_init_append(msg, &args);
    str = "org.bluez.Adapter1";
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &str))
        goto EXIT;
    str = "Powered";
    if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &str))
        goto EXIT;
    if (!dbus_message_iter_open_container(&args, DBUS_TYPE_VARIANT, DBUS_TYPE_BOOLEAN_AS_STRING, &args_a))
        goto EXIT;
    if (!dbus_message_iter_append_basic(&args_a, DBUS_TYPE_BOOLEAN, &v))
        goto EXIT;
    if (!dbus_message_iter_close_container(&args, &args_a))
        goto EXIT;
    if (!dbus_connection_send(conn, msg, NULL))
        goto EXIT;
    dbus_connection_flush(conn);

    for (i = 30; i > 0; i--)
    {
        if (_is_powered(conn, hci_obj) == on)
            break;
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to set 'Powered'(%u) \"%s\" !\n", on, hci_obj);
        goto EXIT;
    }

    ret = 0;

EXIT:
    dbus_message_unref(msg);
    return ret;
}


int _is_discovering(DBusConnection *conn, const char *hci_obj)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    dbus_bool_t v;


    msg = get_property(conn, "org.bluez",
                             hci_obj,
                             "org.bluez.Adapter1",
                             "Discovering");
    if (NULL == msg)
    {
        ERROR("failed to get 'Discovering' \"%s\" !\n", hci_obj);
        return 0;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &v);

EXIT:
    dbus_message_unref(msg);
    return !!v;
}
int set_discovering(DBusConnection *conn, const char *hci_obj, int on)
{
    DBusMessage *msg;
    int i;


    on = !!on;
    if (on)
        DEBUG("scan on");
    else
        DEBUG("scan off");

    if ((NULL == conn) || (NULL == hci_obj))
        return -1;

    if (!has_object(conn, "org.bluez", hci_obj))
    {
        ERROR("hci obj not exist \"%s\" !", hci_obj);
        return -1;
    }
    if (_is_discovering(conn, hci_obj) == on)
        return 0;

    if (on)
        msg = dbus_message_new_method_call("org.bluez",
                                           hci_obj,
                                           "org.bluez.Adapter1",
                                           "StartDiscovery");
     else
        msg = dbus_message_new_method_call("org.bluez",
                                           hci_obj,
                                           "org.bluez.Adapter1",
                                           "StopDiscovery");
    if (NULL == msg)
        return -1;
    if (!dbus_connection_send(conn, msg, NULL))
    {
        dbus_message_unref(msg);
        return -1;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    for (i = 30; i > 0; i--)
    {
        if (_is_discovering(conn, hci_obj) == on)
            break;
        //if (on)
            //DEBUG("wait scan on");
        //else
            //DEBUG("wait scan off");
        usleep(300*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to set 'Discovering'(%u) \"%s\" !\n", on, hci_obj);
        return -1;
    }

    return 0;
}


int _is_connected(DBusConnection *conn, const char *dev_obj)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    dbus_bool_t v;


    msg = get_property(conn, "org.bluez",
                             dev_obj,
                             "org.bluez.Device1",
                             "Connected");
    if (NULL == msg)
    {
        ERROR("failed to get 'Connected' \"%s\" !\n", dev_obj);
        return 0;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &v);

EXIT:
    dbus_message_unref(msg);
    return !!v;
}
int set_connect(DBusConnection *conn, const char *dev_obj, int on)
{
    DBusMessage* msg;
    int i = 0;


    on =!!on;
    if (on)
        DEBUG("connect dev");
    else
        DEBUG("disconnect dev");

    if ((NULL == conn) || (NULL == dev_obj))
        return 0;

    if (on)
    {
        if (bluelock_debug)
        {
            printf("--BlueLock-- find dev ");
            fflush(stdout);
        }
        for (i = 70; i > 0; i--)
        {
            if (has_object(conn, "org.bluez", dev_obj))
                break;
            if (bluelock_debug)
            {
                printf(".");
                fflush(stdout);
            }
            usleep(300*1000);
        }
        if (bluelock_debug)
            printf("\n");
        if (0 >= i)
        {
            ERROR("failed to find dev \"%s\" !\n", dev_obj);
            return -1;
        }
    }
    else
    {
        if (!has_object(conn, "org.bluez", dev_obj))
            return 0;
    }
    if (_is_connected(conn, dev_obj) == on)
        return 0;

    if (on)
        msg = dbus_message_new_method_call("org.bluez",
                                           dev_obj,
                                           "org.bluez.Device1",
                                           "Connect");
    else
        msg = dbus_message_new_method_call("org.bluez",
                                           dev_obj,
                                           "org.bluez.Device1",
                                           "Disconnect");
    if (NULL == msg)
        return -1;
    if (!dbus_connection_send(conn, msg, NULL))
    {
        dbus_message_unref(msg);
        return -1;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    if (bluelock_debug)
    {
        if (on)
            printf("--BlueLock-- wait connect ");
        else
            printf("--BlueLock-- wait disconnect ");
        fflush(stdout);
    }
    for (i = 100; i > 0; i--)
    {
        if (_is_connected(conn, dev_obj) == on)
            break;
        if (bluelock_debug)
        {
            printf(".");
            fflush(stdout);
        }
        usleep(300*1000);
    }
    if (bluelock_debug)
        printf("\n");
    if (0 >= i)
    {
        if (on)
            ERROR("failed to connect to dev \"%s\" !", dev_obj);
        else
            ERROR("failed to disconnect to dev \"%s\" !", dev_obj);
        return -1;
    }

    return 0;
}


int _is_notifying(DBusConnection *conn, const char *gatt_obj)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    dbus_bool_t v;


    msg = get_property(conn, "org.bluez",
                             gatt_obj,
                             "org.bluez.GattCharacteristic1",
                             "Notifying");
    if (NULL == msg)
    {
        ERROR("failed to get 'Notifying' \"%s\" !\n", gatt_obj);
        return 0;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &v);

EXIT:
    dbus_message_unref(msg);
    return !!v;
}
int set_notifying(DBusConnection *conn, const char *gatt_obj, int on)
{
    DBusMessage *msg;
    int i;


    on = !!on;
    if (on)
        DEBUG("start notify");
    else
        DEBUG("stop notify");

    if ((NULL == conn) || (NULL == gatt_obj))
        return -1;

    for (i = 20; i > 0; i--)
    {
        if (has_object(conn, "org.bluez", gatt_obj))
            break;
        //DEBUG("wait gatt read obj \"%s\"", gatt_obj);
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to find gatt read obj \"%s\" !\n", gatt_obj);
        return -1;
    }
    if (_is_notifying(conn, gatt_obj) == on)
        return 0;
    DEBUG("need to set notify");

    if (on)
        msg = dbus_message_new_method_call("org.bluez",
                                           gatt_obj,
                                           "org.bluez.GattCharacteristic1",
                                           "StartNotify");
    else
        msg = dbus_message_new_method_call("org.bluez",
                                           gatt_obj,
                                           "org.bluez.GattCharacteristic1",
                                           "StopNotify");
    if (NULL == msg)
        return -1;

    if (!dbus_connection_send(conn, msg, NULL))
        return -1;
    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    for (i = 20; i > 0; i--)
    {
        if (_is_notifying(conn, gatt_obj) == on)
            break;
        //if (on)
            //DEBUG("wait start notify");
        //else
            //DEBUG("wait stop notify");
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to set notify(%u) \"%s\" !", on, gatt_obj);
        return -1;
    }

    return 0;
}


int _get_data_from_replay(DBusMessage *msg, u8 **data)
{
    DBusMessageIter args;
    DBusMessageIter args_a;
    DBusMessageIter args_ae;
    DBusMessageIter args_aev;
    DBusMessageIter args_aeva;
    char *prop_name;
    int len;


    if (!dbus_message_is_signal(msg, "org.freedesktop.DBus.Properties", "PropertiesChanged"))
        return -1;
    if (!dbus_message_iter_init(msg, &args))
        return -1;
    if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        return -1;
    //dbus_message_iter_get_basic(&args, &str);
    //printf("%s\n", str);
    if (!dbus_message_iter_next(&args))
        return -1;
    if (DBUS_TYPE_ARRAY != (dbus_message_iter_get_arg_type(&args)))
        return -1;
    dbus_message_iter_recurse(&args, &args_a);
    if (DBUS_TYPE_DICT_ENTRY != dbus_message_iter_get_arg_type(&args_a))
        return -1;
    dbus_message_iter_recurse(&args_a, &args_ae);
    if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args_ae))
        return -1;
    dbus_message_iter_get_basic(&args_ae, &prop_name);
    if (0 != strcmp("Value", prop_name))
        return -1;
    if (!dbus_message_iter_next(&args_ae))
        return -1;
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args_ae))
        return -1;
    dbus_message_iter_recurse(&args_ae, &args_aev);
    if (DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&args_aev))
        return -1;

    dbus_message_iter_recurse(&args_aev, &args_aeva);
    dbus_message_iter_get_fixed_array(&args_aeva, data, &len);

    return len;
}
int send_cmd(const BL_ctx_t *ctx, u8 cmd_id, const u8 *indata, u8 *outdata)
{
    char rule[100];
    BL_cmd_t cmd;
    u16 crc16;
    DBusError err;
    DBusMessage *msg_send;
    DBusMessage *msg_recv;
    DBusMessageIter args;
    DBusMessageIter args_a;
    DBusMessageIter args_e;
    int i;
    u8 *psend = (u8 *)&cmd;
    u8 *precv;
    int recv_len;
    int ret = -1;


    if ((NULL == ctx) || (NULL == indata) || (NULL == outdata))
        return -1;

    for (i = 30; i > 0; i--)
    {
        if (has_object(ctx->conn, "org.bluez", ctx->gatt_w_obj))
            break;
        //DEBUG("wait gatt write obj");
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to find gatt write obj \"%s\" !\n", ctx->gatt_w_obj);
        return -1;
    }
    for (i = 10; i > 0; i--)
    {
        if (has_object(ctx->conn, "org.bluez", ctx->gatt_r_obj))
            break;
        //DEBUG("wait gatt read obj");
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to find gatt read obj \"%s\" !\n", ctx->gatt_r_obj);
        return -1;
    }

    /* 打开信号接收 */
    if (0 != set_notifying(ctx->conn, ctx->gatt_r_obj, 1))
        return -1;
    if (sizeof(rule) <= snprintf(rule, sizeof(rule), "type='signal',path='%s'", ctx->gatt_r_obj))
    {
        ERROR("rule len exceeds buf len !");
        return -1;
    }
    dbus_error_init(&err);
    dbus_bus_add_match(ctx->conn, rule, &err);
    if (dbus_error_is_set(&err))
    {
        ERROR("dbus_bus_add_match failed !");
        dbus_error_free(&err);
        return -1;
    }
    dbus_connection_flush(ctx->conn);

    /* 发送 */
    cmd.prefix = 0xFB;
    cmd.cmd_id = cmd_id;
    memcpy(cmd.data, indata, sizeof(cmd.data));
    crc16 = get_crc16((u8 *)&cmd, sizeof(cmd) - 2);
    cmd.crc16_h = crc16 >> 8;
    cmd.crc16_l = crc16 & 0xFF;
    if (bluelock_debug)
    {
        printf("--BlueLock-- send cmd:");
        for (i = 0; i < sizeof(cmd); i++)
            printf(" %02x", ((u8 *)&cmd)[i]);
        printf("\n");
    }
    msg_send = dbus_message_new_method_call("org.bluez",
                                            ctx->gatt_w_obj,
                                            "org.bluez.GattCharacteristic1",
                                            "WriteValue");
    if (NULL == msg_send)
        goto EXIT_MATCH;
    dbus_message_iter_init_append(msg_send, &args);
    if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &args_a))
        goto EXIT_SEND;
    if (!dbus_message_iter_append_fixed_array(&args_a, DBUS_TYPE_BYTE, &psend, sizeof(cmd)))
        goto EXIT_SEND;
    if (!dbus_message_iter_close_container(&args, &args_a))
        goto EXIT_SEND;
    if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &args_e))
        goto EXIT_SEND;
    if (!dbus_message_iter_close_container(&args, &args_e))
        goto EXIT_SEND;
    if (!dbus_connection_send(ctx->conn, msg_send, NULL))
        goto EXIT_SEND;
    dbus_connection_flush(ctx->conn);

    /* 等待接收信号 */
    if (bluelock_debug)
    {
        printf("--BlueLock-- wait reply ");
        fflush(stdout);
    }
    for (i = 40; i > 0; i--)
    {
        if (!dbus_connection_read_write(ctx->conn, 0))
            goto EXIT_SEND;
        msg_recv = dbus_connection_pop_message(ctx->conn);
        if (NULL == msg_recv)
        {
            if (bluelock_debug)
            {
                printf(".");
                fflush(stdout);
            }
            usleep(100*1000);
            continue;
        }
        recv_len = _get_data_from_replay(msg_recv, &precv);
        if (sizeof(BL_cmd_t) != recv_len)
        {
            dbus_message_unref(msg_recv);
            continue;
        }
        break;
    }
    if (bluelock_debug)
        printf("\n");
    if (0 >= i)
    {
        ERROR("failed to recvive reply !");
        goto EXIT_SEND;
    }
    if (bluelock_debug)
    {
        printf("--BlueLock-- recv cmd: ");
        for (i = 0; i < recv_len; i++)
            printf("%02x ", precv[i]);
        printf("\n");
    }
    crc16 = get_crc16(precv, sizeof(BL_cmd_t) - 2);
    if (   (((BL_cmd_t *)precv)->crc16_h != (crc16 >> 8))
        || (((BL_cmd_t *)precv)->crc16_l != (crc16 & 0xFF)))
    {
        ERROR("reply msg crc16 error !");
        goto EXIT_RECV;
    }
    memcpy(outdata, ((BL_cmd_t *)precv)->data, sizeof(((BL_cmd_t *)0)->data));
    ret = sizeof(((BL_cmd_t *)0)->data);


EXIT_RECV:
    dbus_message_unref(msg_recv);
EXIT_SEND:
    dbus_message_unref(msg_send);
EXIT_MATCH:
    dbus_bus_remove_match(ctx->conn, rule, &err);
    dbus_connection_flush(ctx->conn);
    return ret;
}
int send_cmd_retry(const BL_ctx_t *ctx, u8 cmd_id, const u8 *indata, u8 *outdata, u8 times)
{
    int i;
    int ret;

    if (0 == times)
        times = 1;
    for (i = 0; i < times; i++)
    {
        ret = send_cmd(ctx, cmd_id, indata, outdata);
        if (0 <= ret)
            return ret;
        DEBUG("failed to send_cmd %d times", i + 1);
    }
    return -1;
}


int _get_dev_rssi(DBusConnection* conn, const char *dev_obj, s16 *rssi)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    //char *err_str;


    *rssi = -1000;

    msg = get_property(conn, "org.bluez", dev_obj, "org.bluez.Device1", "RSSI");
    if (NULL == msg)
    {
        ERROR("failed to get dev 'RSSI' \"%s\" !", dev_obj);
        return -1;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        //dbus_message_iter_get_basic(&args, &err_str);
        //ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_INT16 != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, rssi);
    dbus_message_unref(msg);

    return 0;

EXIT:
    dbus_message_unref(msg);
    return -1;
}

int _get_dev_name(DBusConnection* conn, const char *dev_obj, char *name, u32 len)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    //char *err_str;
    char *pname;


    name[0] = 0;

    msg = get_property(conn, "org.bluez", dev_obj, "org.bluez.Device1", "Name");
    if (NULL == msg)
    {
        ERROR("failed to get dev 'Name' \"%s\" !", dev_obj);
        return -1;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        //dbus_message_iter_get_basic(&args, &err_str);
        //ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &pname);
    dbus_message_unref(msg);
    snprintf(name, len, "%s", pname);

    return 0;

EXIT:
    dbus_message_unref(msg);
    return -1;
}

int _get_dev_addr(DBusConnection* conn, const char *dev_obj, char *addr, u32 len)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    //char *err_str;
    char *paddr;
    int _len;


    addr[0] = 0;

    msg = get_property(conn, "org.bluez", dev_obj, "org.bluez.Device1", "Address");
    if (NULL == msg)
    {
        ERROR("failed to get dev 'Address' \"%s\" !", dev_obj);
        return -1;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        //dbus_message_iter_get_basic(&args, &err_str);
        //ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &paddr);
    dbus_message_unref(msg);
    _len = snprintf(addr, len, "%s", paddr);
    if (len <= _len)
        return -1;

    return 0;

EXIT:
    dbus_message_unref(msg);
    return -1;
}

int _get_gatt_uuid(DBusConnection* conn, const char *gatt_obj, char *uuid, u32 len)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter args_v;
    //char *err_str;
    char *puuid;
    int _len;


    uuid[0] = 0;

    msg = get_property(conn, "org.bluez", gatt_obj, "org.bluez.GattCharacteristic1", "UUID");
    if (NULL == msg)
    {
        ERROR("failed to get dev 'UUID' \"%s\" !", gatt_obj);
        return -1;
    }
    if (!dbus_message_iter_init(msg, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        //dbus_message_iter_get_basic(&args, &err_str);
        //ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_v);
    if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args_v))
        goto EXIT;
    dbus_message_iter_get_basic(&args_v, &puuid);
    dbus_message_unref(msg);
    _len = snprintf(uuid, len, "%s", puuid);
    if (len <= _len)
        return -1;

    return 0;

EXIT:
    dbus_message_unref(msg);
    return -1;
}




int power_on(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_power(ctx->conn, ctx->hci_obj, 1);
}
int power_off(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_power(ctx->conn, ctx->hci_obj, 0);
}

int scan_on(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_discovering(ctx->conn, ctx->hci_obj, 1);
}
int scan_off(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_discovering(ctx->conn, ctx->hci_obj, 0);
}

int connect_dev(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_connect(ctx->conn, ctx->dev_obj, 1);
}
int disconnect_dev(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_connect(ctx->conn, ctx->dev_obj, 0);
}

int start_notify(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_notifying(ctx->conn, ctx->gatt_r_obj, 1);
}
int stop_notify(const BL_ctx_t *ctx)
{
    if (NULL == ctx)
        return -1;
    return set_notifying(ctx->conn, ctx->gatt_r_obj, 0);
}


int BL_get_dev_list(BL_dev_list_t *list, u32 len)
{
    DBusError err;
    DBusConnection* conn;
    DBusMessage *msg_send;
    DBusMessage *msg_recv;
    DBusMessageIter args;
    DBusMessageIter args_a;
    DBusMessageIter args_ae;
    char *err_str;
    char *obj;
    int ret = -1;
    int i = 0;


    if ((NULL == list) || (0 == len))
        return -1;

    dbus_error_init(&err);
    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err))
    {
        ERROR("dbus_bus_get failed \"%s\" !", err.message);
        dbus_error_free(&err);
        return -1;
    }
    if (NULL == conn)
    {
        ERROR("dbus_bus_get return NULL !");
        return -1;
    }

    set_power(conn, "/org/bluez/hci0", 1);
    set_discovering(conn, "/org/bluez/hci0", 1);

    msg_send = dbus_message_new_method_call("org.bluez", "/",
                                            "org.freedesktop.DBus.ObjectManager",
                                            "GetManagedObjects");
    if (NULL == msg_send)
        return -1;
    msg_recv = method_call_reply(conn, msg_send);
    dbus_message_unref(msg_send);
    if (NULL == msg_recv)
        return -1;

    if (!dbus_message_iter_init(msg_recv, &args))
        goto EXIT;
    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args))
    {
        dbus_message_iter_get_basic(&args, &err_str);
        ERROR("reply error \"%s\" !", err_str);
        goto EXIT;
    }
    if (DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&args))
        goto EXIT;
    dbus_message_iter_recurse(&args, &args_a);
    for (i = 0; i < len; )
    {
        if (DBUS_TYPE_DICT_ENTRY != dbus_message_iter_get_arg_type(&args_a))
            goto CONTINUE;
        dbus_message_iter_recurse(&args_a, &args_ae);
        if (DBUS_TYPE_OBJECT_PATH != dbus_message_iter_get_arg_type(&args_ae))
            goto CONTINUE;
        dbus_message_iter_get_basic(&args_ae, &obj);
        if (strncmp("/org/bluez/hci0/dev_", obj, 20))
            goto CONTINUE;
        if (37 != strlen(obj))
            goto CONTINUE;

        if (0 == _get_dev_addr(conn, obj, list[i].mac,  sizeof(list[i].mac)))
        {
            _get_dev_name(conn, obj, list[i].name,  sizeof(list[i].name));
            _get_dev_rssi(conn, obj, &(list[i].rssi));
            i++;
        }

CONTINUE:
        if (!dbus_message_iter_next(&args_a))
            break;
    }
    ret = i;

EXIT:
    dbus_message_unref(msg_recv);
    return ret;
}


int BL_openlock(const char *mac)
{
    BL_ctx_t ctx;
    DBusError err;
    u8 key_ori[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    u8 key_new[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    u8 send[16];
    u8 send_enc[16];
    u8 recv[16];
    u8 recv_enc[16];
    int i;


    if (NULL == mac)
        return -1;

    DEBUG("open lock: \"%s\"", mac);

    dbus_error_init(&err);
    ctx.conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err))
    {
        ERROR("dbus_bus_get failed \"%s\" !", err.message);
        dbus_error_free(&err);
        return -1;
    }
    if (NULL == ctx.conn)
    {
        ERROR("dbus_bus_get return NULL !");
        return -1;
    }

    ctx.hci = 0;
    if (0 > get_hci_obj_str(ctx.hci, ctx.hci_obj, sizeof(ctx.hci_obj)))
        return -1;
    if (0 > get_dev_obj_str(ctx.hci, mac, ctx.dev_obj, sizeof(ctx.dev_obj)))
        return -1;
    if (sizeof(ctx.gatt_w_obj) <= snprintf(ctx.gatt_w_obj, sizeof(ctx.gatt_w_obj), "%s/service0001/char0002", ctx.dev_obj))
    {
        ERROR("gatt_w_obj len err !");
        return -1;
    }
    if (sizeof(ctx.gatt_r_obj) <= snprintf(ctx.gatt_r_obj, sizeof(ctx.gatt_r_obj), "%s/service0001/char0004", ctx.dev_obj))
    {
        ERROR("gatt_r_obj len err !");
        return -1;
    }

    if (0 != power_on(&ctx))
        return -1;
    if (0 != scan_on(&ctx))
        return -1;
    if (0 != connect_dev(&ctx))
        return -1;

    for (i = 30; i > 0; i--)
    {
        if (has_object(ctx.conn, "org.bluez", ctx.gatt_w_obj))
            break;
        //DEBUG("wait gatt write obj");
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to find gatt write obj \"%s\" !\n", ctx.gatt_w_obj);
        return -1;
    }
    for (i = 10; i > 0; i--)
    {
        if (has_object(ctx.conn, "org.bluez", ctx.gatt_r_obj))
            break;
        //DEBUG("wait gatt read obj");
        usleep(100*1000);
    }
    if (0 >= i)
    {
        ERROR("failed to find gatt read obj \"%s\" !\n", ctx.gatt_r_obj);
        return -1;
    }

    /* 获取随机数 */
    memset(send, 0, sizeof(send));
    memcpy(send, key_new, 8);
    memset(send_enc, 0, sizeof(send_enc));
    aes_enc(send_enc, send, key_ori);
    if (bluelock_debug)
    {
        printf("--BlueLock-- send get_random_num:");
        for (i = 0; i < sizeof(send); i++)
            printf(" %02x", send[i]);
        printf("\n");
    }
    if (16 != send_cmd_retry(&ctx, 1, send_enc, recv_enc, 3))
    {
        disconnect_dev(&ctx);
        return -1;
    }
    aes_dec(recv, recv_enc, key_ori);
    if (bluelock_debug)
    {
        printf("--BlueLock-- recv random_num:");
        for (i = 0; i < sizeof(recv); i++)
            printf(" %02x", recv[i]);
        printf("\n");
    }
    memcpy(key_new + 8, recv, 8);

    /* 开锁 */
    memset(send, 0, sizeof(send));
    aes_enc(send_enc, send, key_new);
    DEBUG("send open_lock");
    if (16 != send_cmd_retry(&ctx, 3, send_enc, recv_enc, 3))
    {
        disconnect_dev(&ctx);
        return -1;
    }

    disconnect_dev(&ctx);
    return 0;
}

int BL_poweroff(void)
{
    DBusConnection* conn;
    DBusError err;

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err))
    {
        ERROR("dbus_bus_get failed \"%s\" !", err.message);
        dbus_error_free(&err);
        return -1;
    }
    if (NULL == conn)
    {
        ERROR("dbus_bus_get return NULL !");
        return -1;
    }
    return set_power(conn, "/org/bluez/hci0", 0);
}

int main(void)
{
    BL_dev_list_t a[30];
    int n;
/*
    n = BL_get_dev_list(a, 30);
    printf("soudaole %d\n", n);
    n--;
    for (; n >= 0; n--)
        printf("mac: %s,  rssi:%d,  name: %s\n", a[n].mac, a[n].rssi, a[n].name);
    //return 0;
*/
    for (n = 1; n <= 100; n++)
    {
        printf("\n\n%d:\n", n);
        BL_openlock("18:45:16:8F:F0:14");
        sleep(10);
    }

    return 0;
}
