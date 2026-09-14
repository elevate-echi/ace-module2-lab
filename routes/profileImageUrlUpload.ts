/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function parseIPv6 (ip: string): number[] | null {
  if (net.isIP(ip) !== 6) return null
  let addr = ip.toLowerCase()
  if (addr.includes('.')) {
    const lastColon = addr.lastIndexOf(':')
    const ipv4Part = addr.slice(lastColon + 1)
    if (net.isIP(ipv4Part) !== 4) return null
    const [a, b, c, d] = ipv4Part.split('.').map(Number)
    const hex1 = ((a << 8) | b).toString(16)
    const hex2 = ((c << 8) | d).toString(16)
    addr = addr.slice(0, lastColon) + ':' + hex1 + ':' + hex2
  }

  const parts = addr.split('::')
  if (parts.length > 2) return null

  let words: number[] = []
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':').map(h => parseInt(h, 16)) : []
    const right = parts[1] ? parts[1].split(':').map(h => parseInt(h, 16)) : []
    const middleCount = 8 - left.length - right.length
    if (middleCount < 0) return null
    const middle = new Array(middleCount).fill(0)
    words = [...left, ...middle, ...right]
  } else {
    words = addr.split(':').map(h => parseInt(h, 16))
  }

  if (words.length !== 8 || words.some(w => isNaN(w) || w < 0 || w > 0xffff)) {
    return null
  }
  return words
}

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
    return true
  }
  const [a, b, c] = parts
  // 0.0.0.0/8
  if (a === 0) return true
  // 10.0.0.0/8
  if (a === 10) return true
  // 100.64.0.0/10
  if (a === 100 && b >= 64 && b <= 127) return true
  // 127.0.0.0/8
  if (a === 127) return true
  // 169.254.0.0/16
  if (a === 169 && b === 254) return true
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true
  // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 0) return true
  // 192.0.2.0/24
  if (a === 192 && b === 0 && c === 2) return true
  // 192.88.99.0/24
  if (a === 192 && b === 88 && c === 99) return true
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true
  // 198.18.0.0/15
  if (a === 198 && (b === 18 || b === 19)) return true
  // 198.51.100.0/24
  if (a === 198 && b === 51 && c === 100) return true
  // 203.0.113.0/24
  if (a === 203 && b === 0 && c === 113) return true
  // 224.0.0.0/4 and 240.0.0.0/4
  if (a >= 224) return true
  return false
}

function isPrivateIp (ip: string): boolean {
  const family = net.isIP(ip)
  if (family === 4) {
    return isPrivateIPv4(ip)
  }
  if (family === 6) {
    const words = parseIPv6(ip)
    if (!words) return true
    // Loopback ::1
    if (words.slice(0, 7).every(w => w === 0) && words[7] === 1) return true
    // Unspecified ::
    if (words.every(w => w === 0)) return true
    // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::/96)
    if (words.slice(0, 5).every(w => w === 0) && (words[5] === 0xffff || words[5] === 0)) {
      const v4 = `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`
      return isPrivateIPv4(v4)
    }
    // NAT64 prefix 64:ff9b::/96
    if (words[0] === 0x64 && words[1] === 0xff9b && words.slice(2, 6).every(w => w === 0)) {
      const v4 = `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`
      return isPrivateIPv4(v4)
    }
    // Unique Local fc00::/7
    if ((words[0] & 0xfe00) === 0xfc00) return true
    // Link-Local fe80::/10
    if ((words[0] & 0xffc0) === 0xfe80) return true
    // Multicast ff00::/8
    if ((words[0] & 0xff00) === 0xff00) return true
    // Documentation 2001:db8::/32
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true
    // Discard 100::/64
    if (words[0] === 0x0100 && words.slice(1, 4).every(w => w === 0)) return true
    return false
  }
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  const hostname = parsedUrl.hostname.toLowerCase()
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.endsWith('.arpa')) {
    return false
  }

  const hostWithoutBrackets = hostname.replace(/^\[|\]$/g, '')

  if (net.isIP(hostWithoutBrackets)) {
    return !isPrivateIp(hostWithoutBrackets)
  }

  try {
    const addresses = await dns.promises.lookup(hostWithoutBrackets, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    return addresses.every(addr => !isPrivateIp(addr.address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url !== 'string' || !(await isSafeUrl(url))) {
          res.status(400)
          next(new Error('Invalid image URL'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
