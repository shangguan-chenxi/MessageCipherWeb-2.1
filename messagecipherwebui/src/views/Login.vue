<template>
  <div class="home">
    <LoginWebUI/>
  </div>
</template>

<script>
// @ is an alias to /src
import LoginWebUI from '@/components/LoginWebUI.vue'

export default {
  name: 'Login',
  components: {
    LoginWebUI
  }
}
</script>

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

.home {
    height: 100%;
    background: url("../assets/background.png");
    background-size: contain;
}
</style>
