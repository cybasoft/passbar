import Foundation
import CryptoKit

/// RFC 6238 TOTP. HMAC comes from Apple's CryptoKit; no custom crypto.
public enum TOTP {
    public static func code(for p: TOTPParameters, at date: Date = Date()) -> String? {
        guard let key = base32Decode(p.secretKey), p.period > 0, (6...10).contains(p.digits) else { return nil }
        var counter = UInt64(date.timeIntervalSince1970 / Double(p.period)).bigEndian
        let msg = Data(bytes: &counter, count: 8)
        let sk = SymmetricKey(data: key)
        let mac: [UInt8]
        switch p.algorithm.uppercased() {
        case "SHA256": mac = Array(HMAC<SHA256>.authenticationCode(for: msg, using: sk))
        case "SHA512": mac = Array(HMAC<SHA512>.authenticationCode(for: msg, using: sk))
        default: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: sk))  // RFC 6238 default
        }
        let off = Int(mac[mac.count - 1] & 0x0f)
        let bin = (UInt32(mac[off] & 0x7f) << 24) | (UInt32(mac[off + 1]) << 16)
            | (UInt32(mac[off + 2]) << 8) | UInt32(mac[off + 3])
        var divisor: UInt64 = 1
        for _ in 0..<p.digits { divisor *= 10 }
        let value = String(UInt64(bin) % divisor)
        return String(repeating: "0", count: max(0, p.digits - value.count)) + value
    }

    static func base32Decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, acc = 0
        var out = Data()
        for ch in s.uppercased() where ch != "=" && ch != " " {
            guard let v = alphabet.firstIndex(of: ch) else { return nil }
            acc = ((acc << 5) | v) & 0xffff; bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> bits) & 0xff)) }
        }
        return out.isEmpty ? nil : out
    }
}
