//go:build ios

package udp

// Inside a Network Extension, recvmsg_x on an unconnected UDP socket delivers no data.
const msgxRequiresConnectedSocket = true
