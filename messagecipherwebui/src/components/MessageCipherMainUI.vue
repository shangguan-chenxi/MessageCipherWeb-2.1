<template>
  <div class="MessageCipherMain">
    <el-row class="container">

        <!-- 顶部文字 -->
        <el-col :xs="24" :sm="24" :md="24" :lg="24" :xl="24">
            <p>MessageCipher V2.1 Web(Beta)</p>
        </el-col>

        <!-- 左边 -->
        <el-col :xs="24" :sm="24" :md="10" :lg="10" :xl="10">
            <el-row class="leftRow">
                <el-col>
                    <el-row class="smallCard">
                        <span class="subTitleText">己方RAS公钥(可公开)</span><el-button class="floatRightButton" @click="requestData.yourRsaPubKey = '';" :disabled="groupMode">清空</el-button>
                        <el-input type="textarea" :rows="4" placeholder="己方RAS公钥(可公开)" clearable v-model="requestData.yourRsaPubKey" :disabled="groupMode"></el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <span class="subTitleText">己方RSA私钥(非公开)</span><el-button class="floatRightButton" @click="requestData.yourRsaPriKey = '';" :disabled="groupMode">清空</el-button>
                        <el-input type="textarea" :rows="4" placeholder="己方RSA私钥(没事不要透露)" clearable v-model="requestData.yourRsaPriKey" :disabled="groupMode"></el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <span class="subTitleText">对方RSA公钥</span><el-button class="floatRightButton" @click="requestData.itsRsaPubKey = '';" :disabled="groupMode">清空</el-button>
                        <el-input type="textarea" :rows="4" placeholder="对方RSA公钥" clearable v-model="requestData.itsRsaPubKey" :disabled="groupMode"></el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <span class="subTitleText">通讯密码密文</span><el-button class="floatRightButton" @click="requestData.cryptedMessageAesKey = '';" :disabled="groupMode">清空</el-button>
                        <el-input type="textarea" :rows="4" placeholder="通讯密码密文" clearable v-model="requestData.cryptedMessageAesKey" :disabled="groupMode"></el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <el-button @click="
                            requestData.yourRsaPubKey = '';
                            requestData.yourRsaPriKey = '';
                            requestData.itsRsaPubKey = '';
                            requestData.cryptedMessageAesKey = '';" :disabled="groupMode">重置</el-button>
                        <el-button @click="generateRsaKeyPair();" :disabled="groupMode">生成RSA密钥对</el-button>
                        <el-button @click="generateCryptedMessageAesKey();" :disabled="groupMode">生成密文</el-button>
                        <el-button @click="decryptCryptedMessageAesKey()" :disabled="groupMode">解密密文</el-button>
                    </el-row>
                </el-col>
            </el-row>
        </el-col>

        <!-- 右边 -->
        <el-col :xs="24" :sm="24" :md="14" :lg="14" :xl="14">
            <el-row class="rightRow">
                <el-col>

                    <el-row class="smallCard">
                        <span class="subTitleText" style="margin-bottom: 17px;">通讯密码</span>
                        <el-button type="primary" size="mini" round style="margin-top: -5px;" @click="getServerRsaPubKey()">更新公钥</el-button>
                        <el-switch
                          style="display: block; float: right;"
                          v-model="groupMode"
                          active-color="#13ce66"
                          inactive-color="#0080ff"
                          active-text="群收发模式"
                          inactive-text="点对点模式">
                        </el-switch>
                        <el-input type="password" maxlength="32" placeholder="通讯密码: 16/24/32字符长度" clearable v-model="requestData.messageAesKey" :disabled="groupMode">
                          <el-select v-model="defaultContact" slot="prepend" placeholder="联系人" class="input-with-select" style="width: 110px;" @change="selectContact" :disabled="groupMode">
                            <el-option label="联系人" value=""></el-option>
                            <el-option v-for="item in contacts" :key="item.name" :label="item.name" :value="item.pwd"></el-option>
                          </el-select>
                          <el-button slot="append" icon="el-icon-refresh" @click="requestData.messageAesKey = generateRandomMessageAesKey(); defaultContact = ''" style="background-color: revert; margin-right: 1px;" :disabled="groupMode"></el-button>
                          <el-button slot="append" icon="el-icon-user" @click="addContactDialogShow = true;" style="background-color: gold;" :disabled="groupMode"></el-button>
                        </el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <span class="subTitleText">通讯明文</span>
                        <el-button class="floatRightButton" @click="encryptPlainText()">加密</el-button>
                        <el-button class="floatRightButton" @click="requestData.plainText = '';" style="margin-right: 10px;">清空明文</el-button>
                        <el-input type="textarea" :rows="15" placeholder="明文" clearable v-model="requestData.plainText">
                        </el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <span class="subTitleText">通讯密文</span>
                        <el-button class="floatRightButton" @click="decryptCryptedText()">解密</el-button>
                        <el-button class="floatRightButton" @click="requestData.cryptedText = '';" style="margin-right: 10px;">清空密文</el-button>
                        <el-input type="textarea" :rows="5" placeholder="密文" clearable v-model="requestData.cryptedText"></el-input>
                    </el-row>

                    <el-row class="smallCard">
                        <el-button style="margin-left: auto; margin-right: auto;" @click="
                            requestData.yourRsaPubKey = '';
                            requestData.yourRsaPriKey = '';
                            requestData.itsRsaPubKey = '';
                            requestData.cryptedMessageAesKey = '';
                            requestData.messageAesKey = '';
                            requestData.plainText = '';
                            requestData.cryptedText = '';" :disabled="groupMode">清空所有</el-button>
                    </el-row>

                </el-col>
            </el-row>
        </el-col>

        <!-- 底部文字 -->
        <el-col :xs="24" :sm="24" :md="24" :lg="24" :xl="24">
          <el-link v-if="strictMode" type="success">当前服务器设置为：STRICT 模式</el-link>
          <p>Powered By: <a href="https://chenxi.in/" target="_blank">Chenxi · 晨曦</a> | <el-button type="text" @click="disclaimerShow = true;">Disclaimer · 声明</el-button> | 此版本和V2.01版本的通讯编码互通</p>
        </el-col>
    </el-row>

    <el-dialog
      title="联系人管理"
      :visible.sync="addContactDialogShow"
      :before-close="clearFields"
      width="30%">

      <el-dialog
        width="30%"
        title="编辑联系人"
        :visible.sync="editContactDialogShow"
        append-to-body>
        <el-row class="upperSection">
          <span>
            <el-input placeholder="联系人名称" clearable v-model="editContactName" style="margin-bottom: 5px;"></el-input>
            <el-input type="password" maxlength="32" placeholder="通讯密码: 16/24/32字符长度" clearable v-model="editContactPwd" style="margin-bottom: 5px;">
              <el-button slot="append" icon="el-icon-refresh" @click="editContactPwd = generateRandomMessageAesKey();"></el-button>
            </el-input>
          </span>
        </el-row>
        <span slot="footer" class="dialog-footer">
          <el-button @click="editContactDialogShow = false;">关 闭</el-button>
          <el-button type="primary" @click="editContact" style="float: right;">保 存</el-button>
        </span>
      </el-dialog>

      <el-row class="upperSection">
        <span>
          <el-input placeholder="联系人名称" clearable v-model="contactName" style="margin-bottom: 5px;"></el-input>
          <el-input type="password" maxlength="32" placeholder="通讯密码: 16/24/32字符长度" clearable v-model="contactPassword" style="margin-bottom: 5px;">
            <el-button slot="append" icon="el-icon-refresh" @click="contactPassword = generateRandomMessageAesKey();"></el-button>
          </el-input>
          <el-button type="primary" @click="addContact" style="float: right;">添 加</el-button>
        </span>
      </el-row>

      <hr>

      <el-row class="lowerSection">
        <span>
          <el-row v-for="(item, index) in contacts" :key="item.name" style="margin-bottom: 5px; height: 41px; background-color: aliceblue;">
            <el-col :span="12" style="display: flex; align-items: center; height: 41px"><span>{{item.name}}</span></el-col>
            <el-col :span="12">
              <el-button type="primary" icon="el-icon-edit" circle style="float: right;" @click="editContactDialogShow = true; editContactIndex = index; editContactName = item.name; editContactPwd = item.pwd;"></el-button>
              <el-button type="danger" icon="el-icon-delete" circle style="float: right; margin-right:5px;" @click="removeContact(item.name)"></el-button>
            </el-col>
          </el-row>
        </span>
      </el-row>
      <span slot="footer" class="dialog-footer">
        <el-button @click="addContactDialogShow = false; contactName = ''; contactPassword = '';">关 闭</el-button>
      </span>
    </el-dialog>

    <el-dialog
      title="需要凭据"
      :visible.sync="strictModeAuthDialogShow"
      width="30%">

      <span>
        <el-row>
          <el-col>
            <el-row>当前服务器设置为STRICT模式，需要验证凭据</el-row>
            <el-row>
              <el-input placeholder="凭据 16/24/32位长度" type="password" maxlength="32" clearable v-model="authPassword" style="margin-top: 10px;"></el-input>
              <el-input placeholder="如验证通过则应显示6位数字" type="text" disabled v-model="authCheckCode" style="margin-top: 5px;"></el-input>
            </el-row>
          </el-col>
        </el-row>
      </span>

      <span slot="footer" class="dialog-footer">
        <el-button type="primary" @click="checkAuthPassword()" :disabled="authCheckCode != ''">验证</el-button>
        <el-button type="success" @click="decryptServerPublicKey()" :disabled="authCheckCode ==''">保存</el-button>
      </span>
    </el-dialog>

    <el-dialog
      title="Disclaimer · 声明"
      :visible.sync="disclaimerShow"
      width="30%">

      <span>
        <p>有关MessageCipher的所有程序的源代码均已通过GitHub进行开源</p>
        <p>本Web程序可脱离TLS进行安全传输，服务器不储存任何信息</p>
        <p>源代码： <a href="https://github.com/shangguan-chenxi/MessageCipher-v2.1" target="_blank">Android</a> | <a href="https://github.com/shangguan-chenxi/MessageCipher-v2.1" target="_blank">PC</a> | <a href="https://github.com/shangguan-chenxi/MessageCipherWeb-2.1" target="_blank">Web(Servlet)</a></p>
        <p>版权没有，翻版不究</p>
        <p>Made with ♥ in Sydney · AUSTRALIA</p>
      </span>

      <span slot="footer" class="dialog-footer">
        <el-button @click="disclaimerShow = false;">关 闭</el-button>
      </span>
    </el-dialog>

  </div>
</template>

<script>
import JSEncrypt from 'jsencrypt' // for RSA
import CryptoJS from 'crypto-js' // for AES

export default {
  name: 'MessageCipherMainUI',
  props: {},

  data () {
    return {
      CONST_DEBUG: false,
      disclaimerShow: false,
      groupMode: false,
      requestData: {
        method: '0',
        messageAesKey: '',
        yourRsaPubKey: '',
        yourRsaPriKey: '',
        itsRsaPubKey: '',
        cryptedMessageAesKey: '',
        plainText: '',
        cryptedText: '',
        protectionAesKey: '',
        clientRsaPublicKey: ''
      },
      defaultContact: '',
      contacts: [],
      addContactDialogShow: false,
      contactName: '',
      contactPassword: '',
      editContactDialogShow: false,
      editContactIndex: -1,
      editContactName: '',
      editContactPwd: '',
      encryptor: new JSEncrypt({ default_key_size: 1024 }),
      localProtectionAesKey: '',
      clientRSAPubKey: '',
      clientRSAPriKey: '',
      serverRSAPubKey: '',

      /** 严格模式 */
      encryptedServerRSAPubKey: '',
      encryptedAuthCheckCode: '',
      authCheckCode: '',
      authPassword: '',
      strictModeAuthDialogShow: false,
      strictMode: false
    }
  },
  methods: {
    /** 运行于浏览器本地的函数 */
    selectContact (callBack) {
      if (this.CONST_DEBUG) {
        console.log('选择联系人回调 => ', callBack)
      }
      this.requestData.messageAesKey = callBack
    },
    clearFields () {
      this.contactName = ''
      this.contactPassword = ''
      this.addContactDialogShow = false
    },
    async addContact () {
      var nameCkeckPass = true
      if (this.contactName === '') {
        await this.$message({ message: '联系人姓名不能为空' })
        return
      } else {
        await this.contacts.forEach((item, index) => {
          if (item.name === this.contactName) {
            this.$message({ message: '联系人姓名不能重复' })
            nameCkeckPass = false
          }
        })
      }
      if (!nameCkeckPass) {
        return
      }

      if (this.contactPassword === '') {
        await this.$message({ message: '通讯密码不能为空' })
        return
      }
      if (this.contactPassword.length !== 16 && this.contactPassword.length !== 24 && this.contactPassword.length !== 32) {
        await this.$message({ message: '通讯密码的长度应为16/24/32位' })
        return
      }
      var newContact = {
        name: this.contactName,
        pwd: this.contactPassword
      }
      this.contacts.push(newContact)
      await this.$message({ message: '成功添加联系人: ' + this.contactName })
      this.contactName = ''
      this.contactPassword = ''
    },
    async removeContact (name) {
      await this.contacts.forEach((item, index) => {
        if (item.name === name) {
          this.contacts.splice(index, 1)
          this.$message({ message: '已删除联系人: ' + name })
        }
      })
    },
    async editContact () {
      var nameCkeckPass = true
      if (this.editContactName === '') {
        await this.$message({ message: '联系人姓名不能为空' })
        return
      } else {
        await this.contacts.forEach((item, index) => {
          if (item.name === this.editContactName) {
            this.$message({ message: '联系人姓名不能重复' })
            nameCkeckPass = false
          }
        })
      }
      if (!nameCkeckPass) {
        return
      }

      if (this.editContactPwd === '') {
        await this.$message({ message: '通讯密码不能为空' })
        return
      }
      if (this.editContactPwd.length !== 16 && this.editContactPwd.length !== 24 && this.editContactPwd.length !== 32) {
        await this.$message({ message: '通讯密码的长度应为16/24/32位' })
        return
      }
      var editedContact = {
        name: this.editContactName,
        pwd: this.editContactPwd
      }
      this.contacts.splice(this.editContactIndex, 1, editedContact)
      await this.$message({ message: '已更新联系人' })
      this.editContactDialogShow = false
    },
    base64ToHex (base64String) {
      return Buffer.from(base64String, 'base64').toString('hex').toUpperCase()
    },
    hexToBase64 (hexString) {
      Buffer.from(hexString.toLowerCase(), 'hex').toString('base64')
    },
    creatRandomString (numberFlag, length) {
      var str = numberFlag ? '1234567890' : '`1234567890-=abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+[]{}ABCDEFGHIJKLMNOPQRSTUVWXYZ;:,./<>?\\"'
      var result = ''
      for (var i = length; i > 0; --i) {
        result += str[Math.floor(Math.random() * str.length)]
      }
      return result
    },
    generateBrowserRsaKeyPair () {
      this.encryptor.getKey()
      this.clientRSAPubKey = this.encryptor.getPublicKeyB64()
      this.clientRSAPriKey = this.encryptor.getPrivateKeyB64()
      if (this.CONST_DEBUG) {
        console.log('浏览器公钥：', this.clientRSAPubKey)
        console.log('浏览器私钥：', this.clientRSAPriKey)
      }
    },
    encryptByRsaPublicKey (pubKey, data) {
      this.encryptor.setPublicKey(pubKey)
      return this.encryptor.encrypt(data)
    },
    encryptByRsaPrivateKey (priKey, data) {
      this.encryptor.setPrivateKey(priKey)
      return this.encryptor.encrypt(data)
    },
    decryptByRsaPublicKey (pubKey, data) {
      this.encryptor.setPublicKey(pubKey)
      return this.encryptor.decrypt(data)
    },
    decryptByRsaPrivateKey (priKey, data) {
      this.encryptor.setPrivateKey(priKey)
      return this.encryptor.decrypt(data)
    },
    encryptByAesKey (aesKey, iv, data) {
      var key = CryptoJS.enc.Utf8.parse(aesKey)
      var IV = CryptoJS.enc.Utf8.parse(iv.substring(0, 16))
      var encrypted = CryptoJS.AES.encrypt(data, key, { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
      return encrypted.toString()
    },
    decryptByAesKey (aesKey, iv, data) {
      // var key = CryptoJS.enc.Hex.parse(aesKey)
      // var IV = CryptoJS.enc.Hex.parse(iv.substring(0, 16))
      var key = CryptoJS.enc.Utf8.parse(aesKey)
      var IV = CryptoJS.enc.Utf8.parse(iv.substring(0, 16))
      var decrypted = CryptoJS.AES.decrypt(data, key, { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
      return this.hexToUtf8(decrypted.toString())
      // return Buffer.from(decrypted.toString().slice(2), 'hex').toString('utf8')
    },

    checkAesKeyLength (str) {
      return (str.length === 16 || str.length === 24 || str.length === 32)
    },

    async checkAuthPassword () {
      if (!this.checkAesKeyLength(this.authPassword)) {
        await this.$message({ message: '凭据应为16/24/32位长度' })
        return
      }
      this.authCheckCode = this.decryptByAesKey(this.authPassword, this.authPassword, this.encryptedAuthCheckCode)
      if (this.authCheckCode !== '') {
        await this.$message({ message: '验证通过，请保存' })
        // this.decryptServerPublicKey()
      } else {
        await this.$message({ message: '无效的凭据' })
      }
    },
    async decryptServerPublicKey () {
      this.serverRSAPubKey = this.decryptByAesKey(this.authPassword, this.authPassword, this.encryptedServerRSAPubKey)
      if (this.serverRSAPubKey === '') {
        await this.$message({ message: '解密服务器公钥失败' })
      } else {
        await this.$message({ message: '已保存服务器公钥到浏览器' })
        this.strictModeAuthDialogShow = false
        this.authPassword = ''
      }
      this.authCheckCode = ''

      if (this.CONST_DEBUG) {
        console.log('解密服务器RSA公钥 :: this.serverRSAPubKey => ', this.serverRSAPubKey)
      }
    },

    /**
     * 编码解决方案
     */
    // 这是目前唯一一个能够完整从hex解码到UTF8的函数
    hexToUtf8 (s) {
      return decodeURIComponent(
        s.replace(/\s+/g, '') // remove spaces
          .replace(/[0-9a-f]{2}/g, '%$&') // add '%' before each 2 characters
      )
    },
    utf8ToHex (s) {
      return encodeURIComponent(s).replace(/%/g, '') // remove all '%' characters
    },

    // 西文和半角符号可以转换，中文和全角符号就不行
    hex_to_ascii (str1) {
      var hex = str1.toString()
      var str = ''
      for (var n = 0; n < hex.length; n += 2) {
        str += String.fromCharCode(parseInt(hex.substr(n, 2), 16))
      }
      return str
    },

    // 一个更新的解决方案，用于编码：
    // This is the same for all of the below, and
    // you probably won't need it except for debugging
    // in most cases.
    bytesToHex (bytes) {
      return Array.from(
        bytes,
        byte => byte.toString(16).padStart(2, '0')
      ).join('')
    },

    // You almost certainly want UTF-8, which is
    // now natively supported:
    stringToUTF8Bytes (string) {
      return new TextEncoder().encode(string)
    },

    // But you might want UTF-16 for some reason.
    // .charCodeAt(index) will return the underlying
    // UTF-16 code-units (not code-points!), so you
    // just need to format them in whichever endian order you want.
    stringToUTF16Bytes (string, littleEndian) {
      const bytes = new Uint8Array(string.length * 2)
      // Using DataView is the only way to get a specific
      // endianness.
      const view = new DataView(bytes.buffer)
      for (let i = 0; i !== string.length; i++) {
        view.setUint16(i, string.charCodeAt(i), littleEndian)
      }
      return bytes
    },

    // And you might want UTF-32 in even weirder cases.
    // Fortunately, iterating a string gives the code
    // points, which are identical to the UTF-32 encoding,
    // though you still have the endianess issue.
    stringToUTF32Bytes (string, littleEndian) {
      const codepoints = Array.from(string, c => c.codePointAt(0))
      const bytes = new Uint8Array(codepoints.length * 4)
      // Using DataView is the only way to get a specific
      // endianness.
      const view = new DataView(bytes.buffer)
      for (let i = 0; i !== codepoints.length; i++) {
        view.setUint32(i, codepoints[i], littleEndian)
      }
      return bytes
    },

    // 例子：
    // bytesToHex(stringToUTF8Bytes("hello 漢字 👍"))
    // "68656c6c6f20e6bca2e5ad9720f09f918d"

    // bytesToHex(stringToUTF16Bytes("hello 漢字 👍", false))
    // "00680065006c006c006f00206f225b570020d83ddc4d"

    // bytesToHex(stringToUTF16Bytes("hello 漢字 👍", true))
    // "680065006c006c006f002000226f575b20003dd84ddc"

    // bytesToHex(stringToUTF32Bytes("hello 漢字 👍", false))
    // "00000068000000650000006c0000006c0000006f0000002000006f2200005b57000000200001f44d"

    // bytesToHex(stringToUTF32Bytes("hello 漢字 👍", true))
    // "68000000650000006c0000006c0000006f00000020000000226f0000575b0000200000004df40100"

    // 对于解码，通常要简单得多，您只需要：
    hexToBytes (hex) {
      const bytes = new Uint8Array(hex.length / 2)
      for (let i = 0; i !== bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
      }
      return bytes
    },

    // 然后使用的编码参数TextDecoder：

    // UTF-8 is default
    // new TextDecoder().decode(hexToBytes("68656c6c6f20e6bca2e5ad9720f09f918d"));
    // but you can also use:
    // new TextDecoder("UTF-16LE").decode(hexToBytes("680065006c006c006f002000226f575b20003dd84ddc"))
    // new TextDecoder("UTF-16BE").decode(hexToBytes("00680065006c006c006f00206f225b570020d83ddc4d"));
    // "hello 漢字 👍"

    // 以下是允许的编码名称列表：https : //www.w3.org/TR/encoding/#names-and-labels

    // 您可能会注意到 UTF-32 不在该列表中，这很痛苦，因此：
    bytesToStringUTF32 (bytes, littleEndian) {
      const view = new DataView(bytes.buffer)
      const codepoints = new Uint32Array(view.byteLength / 4)
      for (let i = 0; i !== codepoints.length; i++) {
        codepoints[i] = view.getUint32(i * 4, littleEndian)
      }
      return String.fromCodePoint(...codepoints)
    },

    // 然后：
    // bytesToStringUTF32(hexToBytes("00000068000000650000006c0000006c0000006f0000002000006f2200005b57000000200001f44d"), false)
    // bytesToStringUTF32(hexToBytes("68000000650000006c0000006c0000006f00000020000000226f0000575b0000200000004df40100"), true)
    // "hello 漢字 👍"

    /** 运行于服务器的函数 */
    // 0：加载的时候要运行的
    getServerRsaPubKey () {
      this.serverRSAPubKey = ''
      this.authPassword = ''
      this.authCheckCode = ''
      var dataPack = {
        method: '0'
      }
      this.$axios.post('', dataPack).then((res) => {
        if (res.data.code === '200') {
          if (res.data.strictMode === 'true') {
            this.encryptedServerRSAPubKey = res.data.result
            this.encryptedAuthCheckCode = res.data.authCheckCode
            this.strictModeAuthDialogShow = true
            this.strictMode = true
          } else {
            this.strictMode = false
            this.serverRSAPubKey = res.data.result
            if (this.serverRSAPubKey !== '') {
              this.$message({ message: '成功获取服务器公钥' })
            } else {
              this.$message({ message: '获取服务器公钥失败' })
            }
          }
          if (this.CONST_DEBUG) {
            console.log('获取服务器RSA公钥 :: res.data => ', res.data)
            console.log('获取服务器RSA公钥 :: this.strictModeAuthDialogShow => ', this.strictModeAuthDialogShow)
            console.log('获取服务器RSA公钥 :: this.serverRSAPubKey => ', this.serverRSAPubKey)
          }
        } else {
          this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
        }
      })
    },

    // 1
    generateRsaKeyPair () {
      if (this.CONST_DEBUG) { console.log('获取RSA密钥对') }
      if (this.serverRSAPubKey === '') {
        this.$message({ message: '无服务器公钥，不能进行操作' })
        return
      }
      this.protectionAesKey = this.creatRandomString(false, 32)
      var encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey)
      var dataPack = {
        method: '1',
        protectionAesKey: encryptedProtectionAesKey
      }
      this.$axios.post('', dataPack).then((res) => {
        if (this.CONST_DEBUG) {
          console.log('生成密钥对 :: 数据包 -> ', res.data)
        }
        if (res.data.code === '200') {
          var publicKey = res.data.publicKey
          var privateKey = res.data.privateKey
          this.requestData.yourRsaPubKey = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, publicKey)
          this.requestData.yourRsaPriKey = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, privateKey)
          if (this.requestData.yourRsaPubKey !== '' && this.requestData.yourRsaPriKey !== '') {
            this.$message({ message: '成功获取密钥对' })
          } else {
            this.$message({ message: '生成RSA密钥对：前端解密数据失败' })
          }
        } else {
          this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
        }
      })
    },

    // 2 生成通讯密码交换密文
    async generateCryptedMessageAesKey () {
      if (this.CONST_DEBUG) { console.log('生成通讯密码密文') }
      if (this.serverRSAPubKey === '') {
        this.$message({ message: '无服务器公钥，不能进行操作' })
        return
      }
      var pass = true
      if (this.requestData.yourRsaPubKey === '') {
        await this.$message({ message: '己方RSA公钥不能为空' })
        pass = false
      }
      if (this.requestData.yourRsaPriKey === '') {
        await this.$message({ message: '己方RSA私钥不能为空' })
        pass = false
      }
      if (this.requestData.itsRsaPubKey === '') {
        await this.$message({ message: '对方RSA公钥不能为空' })
        pass = false
      }
      if (this.requestData.messageAesKey === '') {
        await this.$message({ message: '通讯密码不能为空' })
        pass = false
      } else {
        if (!this.checkAesKeyLength(this.requestData.messageAesKey)) {
          await this.$message({ message: '通讯密码的长度应为16/24/32位' })
          pass = false
        }
      }

      if (pass) {
        this.protectionAesKey = this.creatRandomString(false, 32)
        var encryptedPubliceKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.yourRsaPubKey)
        var encryptedPrivateKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.yourRsaPriKey)
        var encryptedItsPubKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.itsRsaPubKey)
        var encryptedMessageAesKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.messageAesKey)
        var encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey)
        var dataPack = {
          method: '2',
          yourRSAPubKey: encryptedPubliceKey,
          yourRSAPriKey: encryptedPrivateKey,
          itsRSAPubKey: encryptedItsPubKey,
          messageAesKey: encryptedMessageAesKey,
          protectionAesKey: encryptedProtectionAesKey // 用服务器私钥加密
        }
        await this.$axios.post('', dataPack).then((res) => {
          if (res.data.code === '200') {
            this.requestData.cryptedMessageAesKey = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, res.data.result)
            if (this.requestData.cryptedMessageAesKey !== '') {
              this.$message({ message: '成功取得通讯密码密文' })
            } else {
              this.$message({ message: '生成通讯密码密文：前端解密数据失败' })
            }
          } else {
            this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
          }
        })
      }
    },

    // 3 解密通讯密码交换密文
    async decryptCryptedMessageAesKey () {
      if (this.CONST_DEBUG) { console.log('解密通讯密码密文') }
      if (this.serverRSAPubKey === '') {
        this.$message({ message: '无服务器公钥，不能进行操作' })
        return
      }
      var pass = true
      if (this.requestData.yourRsaPubKey === '') {
        await this.$message({ message: '己方RSA公钥不能为空' })
        pass = false
      }
      if (this.requestData.yourRsaPriKey === '') {
        await this.$message({ message: '己方RSA私钥不能为空' })
        pass = false
      }
      if (this.requestData.itsRsaPubKey === '') {
        await this.$message({ message: '对方RSA公钥不能为空' })
        pass = false
      }
      if (this.requestData.cryptedMessageAesKey === '') {
        await this.$message({ message: '通讯密码密文不能为空' })
        pass = false
      }

      if (pass) {
        this.protectionAesKey = this.creatRandomString(false, 32)
        var encryptedPubliceKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.yourRsaPubKey)
        var encryptedPrivateKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.yourRsaPriKey)
        var encryptedItsPubKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.itsRsaPubKey)
        var cryptedMessageAesKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.cryptedMessageAesKey)
        var encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey)
        var dataPack = {
          method: '3',
          yourRSAPubKey: encryptedPubliceKey,
          yourRSAPriKey: encryptedPrivateKey,
          itsRSAPubKey: encryptedItsPubKey,
          cryptedMessageAesKey: cryptedMessageAesKey,
          protectionAesKey: encryptedProtectionAesKey
        }
        this.$axios.post('', dataPack).then((res) => {
          if (res.data.code === '200') {
            this.requestData.messageAesKey = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, res.data.result)
            if (this.requestData.messageAesKey !== '') {
              this.$message({ message: '成功取得通讯密码' })
            } else {
              this.$message({ message: '解密通讯密码密文：前端解密数据失败' })
            }
          } else {
            this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
          }
        })
      }
    },

    // 4：生成随机通讯密码（该函数本地运行）
    generateRandomMessageAesKey () {
      if (this.CONST_DEBUG) { console.log('获取随机通讯密码') }
      /*
      var dataPack = {
        method: '4',
        clientRsaPublicKey: this.clientRSAPubKey
      }
      this.$axios.post('', dataPack).then((res) => {
        if (this.CONST_DEBUG) {
          console.log('获取随机密码 :: 响应码 -> ', res.data.code)
        }
        if (res.data.code === '200') {
          this.requestData.messageAesKey = res.data.result
          this.$message({ message: '成功获取随机通讯密码' })
        } else {
          this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
        }
      })
      */
      this.$message({ message: '成功生成随机通讯密码' })
      return this.creatRandomString(false, 32)
    },

    // 5 / 7： 通讯明文加密
    async encryptPlainText () {
      if (this.CONST_DEBUG) { console.log('使用通讯密码加密通讯明文') }
      if (this.serverRSAPubKey === '') {
        this.$message({ message: '无服务器公钥，不能进行操作' })
        return
      }
      var pass = true
      if (!this.groupMode) {
        if (this.requestData.messageAesKey === '') {
          await this.$message({ message: '通讯密码不能为空' })
          pass = false
        } else {
          if (!this.checkAesKeyLength(this.requestData.messageAesKey)) {
            await this.$message({ message: '通讯密码的长度应为16/24/32位' })
            pass = false
          }
        }
      }
      if (this.requestData.plainText === '') {
        await this.$message({ message: '通讯明文不能为空' })
        pass = false
      }

      if (pass) {
        this.protectionAesKey = this.creatRandomString(false, 32) // 生成保护密码
        var plainText = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.plainText) // 用保护密码加密通讯明文
        let encryptedProtectionAesKey = ''
        var dataPack = {}

        if (this.groupMode) {
          encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey) // 用服务器公钥加密保护密码
          dataPack = {
            method: '7',
            plainText: plainText,
            protectionAesKey: encryptedProtectionAesKey
          }
        } else {
          var encryptedMessageAesKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.messageAesKey) // 用保护密码加密通讯密码
          encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey) // 用服务器公钥加密保护密码
          if (this.CONST_DEBUG) {
            console.log('使用保护密码加密通讯密码的结果 :: protectedMessageAesKey => ', encryptedMessageAesKey)
            console.log('AES保护密码 ::  => ', this.protectionAesKey)
            console.log('使用AES保护密码加密通讯明文的结果 :: plainText => ', plainText)
          }
          dataPack = {
            method: '5',
            messageAesKey: encryptedMessageAesKey,
            plainText: plainText,
            protectionAesKey: encryptedProtectionAesKey
          }
        }
        this.$axios.post('', dataPack).then((res) => {
          if (res.data.code === '200') {
            this.requestData.cryptedText = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, res.data.result)
            if (this.requestData.cryptedText !== '') {
              this.requestData.plainText = ''
              this.$message({ message: '消息加密成功' })
            } else {
              this.$message({ message: '加密通讯明文：前端解密数据失败' })
            }
          } else {
            this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
          }
        })
      }
    },

    // 6 / 8：通讯密文解密
    async decryptCryptedText () {
      if (this.CONST_DEBUG) { console.log('使用通讯密码解密通讯密文') }
      if (this.serverRSAPubKey === '') {
        this.$message({ message: '无服务器公钥，不能进行操作' })
        return
      }
      var pass = true
      if (!this.groupMode) {
        if (this.requestData.messageAesKey === '') {
          await this.$message({ message: '通讯密码不能为空' })
          pass = false
        } else {
          if (!this.checkAesKeyLength(this.requestData.messageAesKey)) {
            await this.$message({ message: '通讯密码的长度应为16/24/32位' })
            pass = false
          }
        }
      }
      if (this.requestData.cryptedText === '') {
        await this.$message({ message: '通讯密文不能为空' })
        pass = false
      }

      if (pass) {
        this.protectionAesKey = this.creatRandomString(false, 32) // 生成保护密码
        var cryptedText = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.cryptedText) // 用保护密码加密通讯密文
        let encryptedProtectionAesKey = ''
        var dataPack = {}

        if (this.groupMode) {
          encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey) // 用服务器公钥加密保护密码
          dataPack = {
            method: '8',
            cryptedText: cryptedText,
            protectionAesKey: encryptedProtectionAesKey
          }
        } else {
          var encryptedMessageAesKey = this.encryptByAesKey(this.protectionAesKey, this.protectionAesKey, this.requestData.messageAesKey) // 用保护密码加密通讯密码
          encryptedProtectionAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.protectionAesKey) // 用服务器公钥加密保护密码
          dataPack = {
            method: '6',
            messageAesKey: encryptedMessageAesKey,
            cryptedText: cryptedText,
            protectionAesKey: encryptedProtectionAesKey
          }
        }

        this.$axios.post('', dataPack).then((res) => {
          if (res.data.code === '200') {
            this.requestData.plainText = this.decryptByAesKey(this.protectionAesKey, this.protectionAesKey, res.data.result)
            if (this.requestData.plainText !== '') {
              this.requestData.cryptedText = ''
              this.$message({ message: '消息解密成功' })
            } else {
              this.$message({ message: '解密通讯明文：前端解密数据失败' })
            }
          } else {
            this.$message({ message: '错误信息: ' + res.data.result + ' | 错误码: ' + res.data.code })
          }
        })
      }
    }
  },
  created () {
    this.getServerRsaPubKey()
    // this.generateBrowserRsaKeyPair()
  }
}
</script>

<style scoped>
.MessageCipherMain{
  height: 100%;
  max-width: 1300px;
  margin-left: auto;
  margin-right: auto;
  background: url("../assets/background.png");
}

.container{
    /*
  height: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
  */
}

.leftRow{
  margin-left: 20px;
  margin-right:20px;
  margin-bottom: 5px;
  background-color: rgba(150,200,240,0.7);
  border-radius: 10px;
}

.rightRow{
  margin-left: 20px;
  margin-right:20px;
  margin-bottom: 5px;
  background-color: rgba(220,128,200,0.7);
  border-radius: 10px;
}

.subTitleText{
    float: left;
}
.floatRightButton{
    float: right;
}

.smallCard{
    margin: 20px 20px 20px 20px;
}
</style>
