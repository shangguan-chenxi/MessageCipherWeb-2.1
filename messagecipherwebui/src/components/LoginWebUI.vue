<template>
  <div class="loginMainPage">
    <el-row class="login">
      <el-col style='margin-left: auto; margin-right: auto;justify-content: center; align-items: center;'>
        <el-row>
          <p>MessageCipher V2.1(Web)</p>
        </el-row>

        <el-row>
          <el-input placeholder="输入口令" v-model="authCode"></el-input>
        </el-row>

        <el-row style="margin-top: 20px;">
          <el-button class="submitBtn">验证</el-button>
        </el-row>
      </el-col>
    </el-row>
  </div>
</template>

<script>
export default {
  name: 'LoginWebUI',
  props: {},

  data () {
    return {
      authCode: ''
    }
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}

.loginMainPage {
  height: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
}
.login {
  width: 350px;
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
