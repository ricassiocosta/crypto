import crypto from 'crypto'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'

dotenv.config()
const CRYPTO_CONFIG = {
  algorithm: "aes256",
  secret: process.env.CRYPTO_SECRET as string,
  key: process.env.CRYPTO_KEY as string,
}

interface Message {
  message: string,
  hash: string
}

async function sendMessage(message: string, secret: string, key: string) {
  const secretMessage = message + secret
  const messageHash = await bcrypt.hash(secretMessage, 8)
  const messageObj: Message = {
    message: message,
    hash: messageHash
  }

  const newMessage = JSON.stringify(messageObj)
  const cipher = crypto.createCipher(CRYPTO_CONFIG.algorithm, key)
  let encryptedMessage = cipher.update(newMessage, "utf8", "hex")
  encryptedMessage += cipher.final("hex")
  return encryptedMessage
}

async function receiveMessage(cyphedMessage: string, secret: string, key: string) {
  const decipher = crypto.createDecipher(CRYPTO_CONFIG.algorithm, key)
  let decryptedMessage = decipher.update(cyphedMessage, "hex", "utf8")
  decryptedMessage += decipher.final("utf8")

  const messageObj = JSON.parse(decryptedMessage) as Message
  const secretMessage = messageObj.message + secret

  const messageIsUntouched = await bcrypt.compare(secretMessage, messageObj.hash)
  if (!messageIsUntouched) {
    throw new Error("Message was breached!")
  }

  return messageObj.message
}

async function test() {
  const message = "Eu quero meu 10 haha!"
  const ciphedMessage = await sendMessage(message, CRYPTO_CONFIG.secret, CRYPTO_CONFIG.key)
  const deciphedMessage = await receiveMessage(ciphedMessage, CRYPTO_CONFIG.secret, CRYPTO_CONFIG.key)

  console.log(deciphedMessage)
}

test()