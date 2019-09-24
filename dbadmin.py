#!/usr/bin/python
# -*- coding:utf-8 -*-

import pymysql
import hashlib
import base64
import os
import sys
from Crypto.Cipher import AES


class DbManager(object):
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 3336
        self.database = 'dbadmin'
        self.username = 'dbadmin'
        self.salt = input("请输入密钥:").encode("utf-8")
        self.password = self.aesDecrypt('rgYxBTWHK/sUOZZcMLMtc69LOPrraM2AD4MkHiMynBE=')
        self.db = pymysql.connect(self.host, self.username, self.password, self.database, self.port, connect_timeout=120, charset='utf8')
        self.mysql_cli = "/usr/local/bin/mysql"
        self.redis_cli = "/usr/local/bin/redis-cli"
        self.mongo_cli = "/usr/local/mongodb/bin/mongo"

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)

    def aesEncrypt(self, content):
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        content1 = pad(content)
        text = self.add_to_16(content1)
        cryptos = AES.new(self.salt, AES.MODE_ECB)
        cipher_text = cryptos.encrypt(text)
        aes_base64 = base64.encodebytes(cipher_text)
        m = str(aes_base64, encoding="utf-8")
        return m

    def aesDecrypt(self, text):
        unpad = lambda s: s[0:-ord(s[-1])]
        cryptos = AES.new(self.salt, AES.MODE_ECB)
        base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
        content = cryptos.decrypt(base64_decrypted).decode('utf-8')
        decrypted_text = unpad(content)
        decrypted_code = decrypted_text.rstrip('\0')
        return decrypted_code

    def dml(self, sql):
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()
        finally:
            cursor.close()

    def query_one(self, sql):
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
        except:
            print("查询异常:", cursor.DatabaseError)
        finally:
            cursor.close()
        return cursor.fetchone()

    def query_many(self, sql):
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
        except:
            print("查询异常:", cursor.DatabaseError)
        finally:
            cursor.close()
        return cursor.fetchall()

    def md5(self, pwd):
        obj = hashlib.md5(self.salt)
        obj.update(pwd.encode('utf-8'))
        return obj.hexdigest()

    def add_inst(self):
        inst_host = input("请输入实例IP:")
        inst_port = input("请输入实例端口:")
        inst_type = input("请输入数据库类型(redis,mysql,mongo):")
        inst_role = input("请输入实例角色(master,slave,mongos,mongo):")
        # inst_port = "6379"
        # inst_type = "redis"
        # inst_role = "master"
        inst_user = input("请输入实例用户名:")
        inst_password = self.aesEncrypt(input("请输入实例密码:"))
        inst_remark = input("请输入备注信息:")
        sql = "insert into dbadmin_info(host,port,type,role,username,password,remark) " \
              "values('{}',{},'{}','{}','{}','{}','{}')".format(
            inst_host.strip(), inst_port, inst_type, inst_role, inst_user, inst_password.strip(), inst_remark)
        self.dml("{}".format(sql))

    def get_inst_cmd(self):
        columns = ('host', 'port', 'type', 'username', 'password')
        inst = input("请输入实例IP OR 实例序号:")
        sql = "select host, port, type, username, password from dbadmin_info where host='{}' or id='{}'".format(inst, inst)
        res = dict(zip(columns, self.query_one(sql)))
        password = self.aesDecrypt(res['password'].strip("\n"))
        type = res['type']
        if type == "redis":
            cmd = "{} -h {} -p {} -a {}".format(self.redis_cli, res['host'], res['port'], password)
        elif type == "mysql":
            cmd = "{} -h {} -P {} -u{} -p{} --connect_timeout=10 --prompt='(\\u@\\d)>' --show-warnings".format(
                self.mysql_cli, res['host'], res['port'], res['username'], password)
        elif type == "mongo":
            cmd = "{} mongodb://{}:{}@{}:{}/admin".format(self.mongo_cli,res['username'], password, res['host'], res['port'])
        return cmd

    def my_align(self, _string, _length, _type='L'):
        _str_len = len(_string)
        for _char in _string:
            if u'\u4e00' <= _char <= u'\u9fa5':
                _str_len += 1
        _space = _length - _str_len
        if _type == 'L':
            _left = 0
            _right = _space
        elif _type == 'R':
            _left = _space
            _right = 0
        else:
            _left = _space // 2
            _right = _space - _left
        return ' ' * _left + _string + ' ' * _right

    def get_insts_by_type(self, value):
        sql = "select concat(id,':',host,':',port,':',type,':',role,':',remark) from dbadmin_info where type='{}'".format(value)
        res = self.query_many(sql)
        print("-----------------------------------------------------------------------------------------------------------------------")
        print("|","ID".ljust(4),"|","HOST".ljust(50),"|","PORT".ljust(5),"|","TYPE".ljust(5),"|","ROLE".ljust(6),"|","SERVICE".ljust(30),"|")
        print("-----------------------------------------------------------------------------------------------------------------------")
        for item in res:
            item_str = item[0]
            items = item_str.split(":")
            print("|", self.my_align(items[0],4),
                  "|", self.my_align(items[1],50),
                  "|", self.my_align(items[2],5),
                  "|", self.my_align(items[3],5),
                  "|", self.my_align(items[4],6),
                  "|", self.my_align(items[5],30),"|")
        print("-----------------------------------------------------------------------------------------------------------------------")

    def _close_db(self):
        self.db.close()


if __name__ == '__main__':
    manager = DbManager()
    while True:
        operate = input("""  
1:增加实例
2:登陆实例
4:获取所有mysql实例
5:获取所有mongo实例
6:获取所有redis实例
0:退出当前操作
请选择操作(输入序号):""")
        if operate == "1":
            manager.add_inst()
        elif operate == "2":
            cmd = manager.get_inst_cmd()
            print(cmd)
            os.system(cmd)
            manager._close_db()
            break
        elif operate == '4':
            manager.get_insts_by_type('mysql')
        elif operate == '5':
            manager.get_insts_by_type('mongo')
        elif operate == '6':
            manager.get_insts_by_type('redis')
        elif operate == '0':
            manager._close_db()
            sys.exit()
        else:
            print("请选择正确的选项，如果退出请输入0")
