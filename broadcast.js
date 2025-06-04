async function broadcastMessage(sock, message, jids) {
  if (!jids || jids.length === 0) {
    console.log('⚠️ No contacts provided for broadcast.');
    return;
  }
  console.log(`📤 Sending broadcast to ${jids.length} contacts...`);

  for (const jid of jids) {
    try {
      await sock.sendMessage(jid, { text: message });
      console.log(`✅ Sent to ${jid}`);
    } catch (err) {
      console.error(`❌ Failed to send to ${jid}: ${err.message}`);
    }
  }
}
