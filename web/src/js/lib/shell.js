// App shell behaviour: mobile navigation disclosure and the user menu disclosure.
export default function (Alpine) {
  Alpine.data('shell', () => ({
    navOpen: false, userOpen: false,
    toggleNav() { this.navOpen = !this.navOpen },
    toggleUser() { this.userOpen = !this.userOpen },
    closeUser() { this.userOpen = false },
    escUser() {
      if (!this.userOpen) return
      this.userOpen = false
      const b = this.$refs.userButton
      if (b) b.focus()
    },
    get navAttr() { return this.navOpen ? 'true' : 'false' },
    get navExpanded() { return this.navOpen ? 'true' : 'false' },
    get userExpanded() { return this.userOpen ? 'true' : 'false' },
    get navLabel() { return this.navOpen ? 'Close navigation menu' : 'Open navigation menu' },
  }))
}
