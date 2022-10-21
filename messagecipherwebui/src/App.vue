<template>
  <div id="app">
    <!--<img src="./assets/logo.png">-->
    <div>
    </div>
    <!--<HelloWorld msg="Welcome to Your Vue.js App"/>-->
    <router-view></router-view>
  </div>
</template>

<script>
// import HelloWorld from './components/HelloWorld.vue'
import './assets/all.css'

export default {
  name: 'app',
  components: {
    // HelloWorld
  }
}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 0px;
  /*background-color: rgb(102, 160, 138);*/
}
</style>
