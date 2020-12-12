
typealias Address = Int // alias in order to extend Address and not Int

val suspicious = listOf("123.123.123.123/31", "255.255.255.0/30") // stub

fun isAllowed(incomingIp: String): Boolean {
    val netmask: (Int) -> Int = { if (it > 0) ((0xffffffff shl (32 - it)) ushr 0).toInt() else 0 }
    val contain: Address.(Address, Int) -> Boolean = { a: Address, b: Int -> (a and netmask(b)) == (this and netmask(b)) }
    val toAddress: (String) -> Address = {
        val address = it.split('.').map { it.toIntOrNull() }.filterNotNull().filter { it in 0..255 }
        if (address.size != 4) {
            throw Error("Not a valid IP address: $it")
        }
        (address[0] shl 24) or (address[1] shl 16) or (address[2] shl 8) or address[3]
    }

    suspicious.forEach {
        val (net, mask) = it.split('/')
        if (toAddress(net).contain(toAddress(incomingIp), mask.toInt())) return false
    }

    return true
}
