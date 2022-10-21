<template>
  <div class="home">
    <!--<img alt="Vue logo" src="../assets/logo.png">-->
    <MessageCipherMainUI/>
  </div>
</template>

<script>
// @ is an alias to /src
// import HelloWorld from '@/components/HelloWorld.vue'
import MessageCipherMainUI from '@/components/MessageCipherMainUI.vue'

export default {
  name: 'Home',
  components: {
    MessageCipherMainUI
  }
}
</script>

<style scoped>
.home {
    height: 100%;
}
</style>
