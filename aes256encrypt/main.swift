//
//  main.swift
//  aes256encrypt
//
//  Created by Albert Viilik on 04/01/2021.
//

import Foundation
import CryptoKit

let usage = "./aes256encrypt [--enc/dec] [message] [key]"

if CommandLine.arguments.count < 3 || (CommandLine.arguments[1] != "--enc" && CommandLine.arguments[1] != "--dec") {
    print(usage)
    exit(1)
}

var messageBytes: Data
var keyBytes: Data

guard let keyBytes = CommandLine.arguments[3].data(using: .utf8), let messageBytes = CommandLine.arguments[2].data(using: .utf8) else {
    print("Error: Failed to retrieve message or key bytes!")
    exit(1)
}

let keyHash = SHA256.hash(data: keyBytes)

let symmetricKey = SymmetricKey(data: keyHash)

if (CommandLine.arguments[1] == "--enc") {
    
    guard let sealed = try? AES.GCM.seal(messageBytes, using: symmetricKey) else {
        print("Error: Failed to encrypt!")
        exit(1)
    }
    
    guard let data = sealed.combined else {
        print("Error: Failed to retrieve combined data!")
        exit(1)
    }
    
    print(data.base64EncodedString())
    
} else {
    
    guard let combinedData = Data(base64Encoded: CommandLine.arguments[2]) else {
        print("Error: Failed to retrieve combined data!")
        exit(1)
    }
    
    guard let sealed = try? AES.GCM.SealedBox(combined: combinedData) else {
        print("Error: Failed to construct a sealed box from the data!")
        exit(1)
    }
    
    guard let unsealed = try? AES.GCM.open(sealed, using: symmetricKey) else {
        print("Error: Wrong key!")
        exit(1)
    }
    
    print(String(decoding: unsealed, as: UTF8.self))
}
