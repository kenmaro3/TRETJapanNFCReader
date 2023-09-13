//
//  IndividualNumberReaderReadFunctions.swift
//  TRETJapanNFCReader
//
//  Created by treastrain on 2020/05/10.
//  Copyright © 2020 treastrain / Tanaka Ryoga. All rights reserved.
//

#if os(iOS)
import CoreNFC
#if canImport(TRETJapanNFCReader_MIFARE)
import TRETJapanNFCReader_MIFARE
#endif

import Foundation
import Security
//import SwiftASN1

extension Data {
    func toHexString() -> String {
        var hexString = ""
        for index in 0..<count {
            hexString += String(format: "%02X", self[index])
        }
        return hexString
    }
}

extension String {
    func hexToBytes() -> [UInt8]? {
        let length = count
        if length & 1 != 0 {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length / 2)
        var index = startIndex
        for _ in 0..<length / 2 {
            let nextIndex = self.index(index, offsetBy: 2)
            if let b = UInt8(self[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
}

public struct ASN1PartialParser {
    public private(set) var offset = 0
    public private(set) var length = 0

    public var size: Int {
        return self.offset + self.length
    }

    public init(data: Data) throws {
        try self.parseTag(data: data)
        try self.parseLength(data: data)
    }

    private mutating func parseTag(data: Data) throws {
        let data = data as NSData
        var offset = 1
        if data.length < 2 {
            throw NSError()
        }
        if data[0] & 0x1F == 0x1F {
            offset += 1
            if data.length < 2 || data[1] & 0x80 != 0 {
                throw NSError()
            }
        }
        self.offset = offset
    }

    private mutating func parseLength(data: Data) throws {
        let data = data as NSData
        if self.offset >= data.length {
            throw NSError()
        }
        var b = data[self.offset]
        self.offset += 1
        if b & 0x80 == 0 {
            self.length = Int(b)
        } else {
            let lol = b & 0x7F
            for _ in 0..<lol {
                if self.offset >= data.length {
                    throw NSError()
                }
                b = data[self.offset]
                self.offset += 1
                self.length <<= 8
                self.length |= Int(b)
            }
        }
    }
}

@available(iOS 13.0, *)
extension IndividualNumberReader {
    
    internal func readJPKIToken(_ session: NFCTagReaderSession, _ individualNumberCard: IndividualNumberCard) -> IndividualNumberCard {
        let semaphore = DispatchSemaphore(value: 0)
        var individualNumberCard = individualNumberCard
        let tag = individualNumberCard.tag
        
        self.selectJPKIAP(tag: tag) { (responseData, sw1, sw2, error) in
            self.printData(responseData, sw1, sw2)
            
            if let error = error {
                print(error.localizedDescription)
                session.invalidate(errorMessage: "SELECT JPKIAP\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                return
            }
            
            if sw1 != 0x90 {
                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                return
            }
            
            self.selectEF(tag: tag, data: [0x00, 0x06]) { (responseData, sw1, sw2, error) in
                self.printData(responseData, sw1, sw2)
                
                if let error = error {
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    return
                }
                
                if sw1 != 0x90 {
                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    return
                }
                
                self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: 20) { (responseData, sw1, sw2, error) in
                    self.printData(responseData, sw1, sw2)
                    
                    if let error = error {
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        return
                    }
                    
                    if sw1 != 0x90 {
                        session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                        return
                    }
                    
                    let responseString = String(data: responseData, encoding: .utf8) ?? ""
                    individualNumberCard.data.token = responseString.filter { $0 != " " }
                    semaphore.signal()
                }
            }
        }
        
        semaphore.wait()
        return individualNumberCard
    }
    
    internal func readIndividualNumber(_ session: NFCTagReaderSession, _ individualNumberCard: IndividualNumberCard, cardInfoInputSupportAppPIN: [UInt8]) -> IndividualNumberCard {
        
        if cardInfoInputSupportAppPIN.isEmpty {
            session.invalidate(errorMessage: IndividualNumberReaderError.needPIN.errorDescription!)
            self.delegate?.japanNFCReaderSession(didInvalidateWithError: IndividualNumberReaderError.needPIN)
            return individualNumberCard
        }
        
        let semaphore = DispatchSemaphore(value: 0)
        var individualNumberCard = individualNumberCard
        let tag = individualNumberCard.tag
        
        self.selectCardInfoInputSupportAP(tag: tag) { (responseData, sw1, sw2, error) in
            self.printData(responseData, sw1, sw2)
            
            if let error = error {
                print(error.localizedDescription)
                session.invalidate(errorMessage: "SELECT TextAP\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                return
            }
            
            if sw1 != 0x90 {
                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                return
            }
            
            self.selectEF(tag: tag, data: [0x00, 0x11]) { (responseData, sw1, sw2, error) in
                self.printData(responseData, sw1, sw2)
                
                if let error = error {
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    return
                }
                
                if sw1 != 0x90 {
                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    return
                }
                
                self.verify(tag: tag, pin: cardInfoInputSupportAppPIN) { (responseData, sw1, sw2, error) in
                    self.printData(responseData, sw1, sw2)
                    
                    if let error = error {
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "VERIFY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        return
                    }
                    
                    if sw1 != 0x90 {
                        if sw1 == 0x63 {
                            var error = IndividualNumberReaderError.incorrectPIN(0)
                            switch sw2 {
                            case 0xC1:
                                error = .incorrectPIN(1)
                            case 0xC2:
                                error = .incorrectPIN(2)
                            case 0xC3:
                                error = .incorrectPIN(3)
                            case 0xC4:
                                error = .incorrectPIN(4)
                            case 0xC5:
                                error = .incorrectPIN(5)
                            default:
                                break
                            }
                            print("PIN エラー", error)
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        }
                        session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                        return
                    }
                    
                    self.selectEF(tag: tag, data: [0x00, 0x01]) { (responseData, sw1, sw2, error) in
                        self.printData(responseData, sw1, sw2)
                        
                        if let error = error {
                            print(error.localizedDescription)
                            session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                            return
                        }
                        
                        if sw1 != 0x90 {
                            session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                            return
                        }
                        
                        self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: 17) { (responseData, sw1, sw2, error) in
                            self.printData(responseData, sw1, sw2)
                            
                            if let error = error {
                                print(error.localizedDescription)
                                session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                                return
                            }
                            
                            if sw1 != 0x90 {
                                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                                return
                            }
                            
                            var data = [UInt8](responseData)
                            data.removeFirst()
                            let fields = TLVField.sequenceOfFields(from: data)
                            
                            if let individualNumberData = fields.first?.value, let individualNumber = String(data: Data(individualNumberData), encoding: .utf8) {
                                individualNumberCard.data.individualNumber = individualNumber
                            }
                            
                            semaphore.signal()
                        }
                    }
                }
            }
        }
        
        semaphore.wait()
        return individualNumberCard
    }
    
    internal func get_certificate(_ session: NFCReaderSession, _ individualNumberCard: IndividualNumberCard) -> IndividualNumberCard {
        
        let semaphore = DispatchSemaphore(value: 0)
        var individualNumberCard = individualNumberCard
        let tag = individualNumberCard.tag
        
        self.selectJPKIAP(tag: tag){(responseData, sw1, sw2, error) in
            self.printData(responseData, sw1, sw2)
            if let error = error{
                session.invalidate(errorMessage: "SELECT JPKIAP\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                return
            }
            
            if sw1 != 0x90{
                session.invalidate(errorMessage: "error: status1: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                return
            }
            
            self.selectEF(tag: tag, data: [0x00, 0x0A]){ (responseData, sw1, sw2, error) in
                self.printData(responseData, sw1, sw2)
                
                if let error = error{
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EC\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    return
                }
                
                if sw1 != 0x90{
                    session.invalidate(errorMessage: "error: status2: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    return
                }
                
                self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: 7){(responseData, sw1, sw2, error) in
                    self.printData(responseData, sw1, sw2)
                    
                    if let error = error{
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        return
                    }
                    
                    if sw1 != 0x90{
                        session.invalidate(errorMessage: "error: status3: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                        return
                    }
                    
                    guard let asn1 = try? ASN1PartialParser(data: responseData) else {
                        session.invalidate(errorMessage: "ASN1PartialParser Error")
                        return
                    }
                    
                    self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: asn1.size){ (responseData, sw1, sw2, error) in
                        self.printData(responseData, sw1, sw2)
                        
                        if let error = error {
                            print(error.localizedDescription)
                            session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                            return
                        }
                        
                        if sw1 != 0x90{
                            session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                            return
                        }
                        
                        individualNumberCard.data.certificate_pem_before = responseData
                        
//                        guard let x509 = try? X509Certificate(data: Data(responseData)) else {
//                            session.invalidate(errorMessage: "X509Certificate Parse Error")
//                            return
//                        }
//
//                        individualNumberCard.data.certificate_raw = responseData
//
//                        let INDENTATION = "\n"
//                        let BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
//                        let END_CERT = "-----END CERTIFICATE-----"
//
//                        let encoded = responseData.base64EncodedString(options: Data.Base64EncodingOptions.lineLength64Characters)
//
//                        individualNumberCard.data.certificate_pem = BEGIN_CERT + INDENTATION + encoded + INDENTATION + END_CERT
                        
                        semaphore.signal()
                        
                    }
                }
            }
            
        }
        
        semaphore.wait()
        return individualNumberCard
        
    }
    
    internal func signCertificate(_ session: NFCReaderSession, _ individualNumberCard: IndividualNumberCard, cardInfoInputSupportAppPIN: [UInt8], data_sha1: String) -> IndividualNumberCard {
        
        let semaphore = DispatchSemaphore(value: 0)
        var individualNumberCard = individualNumberCard
        let tag = individualNumberCard.tag
        
        self.selectJPKIAP(tag: tag){(responseData, sw1, sw2, error) in
            self.printData(responseData, sw1, sw2)
            if let error = error{
                session.invalidate(errorMessage: "SELECT JPKIAP\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                return
            }
            
            if sw1 != 0x90{
                session.invalidate(errorMessage: "error: status1: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                return
            }
            
            self.selectEF(tag: tag, data: [0x00, 0x18]){ (responseData, sw1, sw2, error) in
                self.printData(responseData, sw1, sw2)
                
                if let error = error {
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    return
                }
                
                if sw1 != 0x90 {
                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    return
                }
                self.verify(tag: tag, pin: cardInfoInputSupportAppPIN){ (responseData, sw1, sw2, error) in
                    self.printData(responseData, sw1, sw2)
                    print("here0000")
                    
                    if let error = error {
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "VERIFY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        return
                    }
                    
                    if sw1 != 0x90 {
                        if sw1 == 0x63 {
                            var error = IndividualNumberReaderError.incorrectPIN(0)
                            switch sw2 {
                            case 0xC1:
                                error = .incorrectPIN(1)
                            case 0xC2:
                                error = .incorrectPIN(2)
                            case 0xC3:
                                error = .incorrectPIN(3)
                            case 0xC4:
                                error = .incorrectPIN(4)
                            case 0xC5:
                                error = .incorrectPIN(5)
                            default:
                                break
                            }
                            print("PIN エラー", error)
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        }
                        session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                        return
                    }
                    
                    let header = "3021300906052B0E03021A05000414"
                    let digestInfo = header.hexToBytes()! + data_sha1.hexToBytes()!
                    print("digestInfo: \(Data(digestInfo).toHexString())")
                    
                    self.selectEF(tag: tag, data: [0x00, 0x17]){ (responseData, sw1, sw2, error) in
                        self.printData(responseData, sw1, sw2)
                        
                        if let error = error {
                            print(error.localizedDescription)
                            session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                            return
                        }
                        
                        if sw1 != 0x90 {
                            session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                            return
                        }
                       
                        self.signature(tag: tag, data: digestInfo, p1Parameter: 0x00, p2Parameter: 0x80){ (responseData, sw1, sw2, error) in
                            self.printData(responseData, sw1, sw2)
                            
                            if let error = error {
                                print(error.localizedDescription)
                                session.invalidate(errorMessage: "signature \n\(error.localizedDescription)")
                                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                                return
                            }
                            
                            if sw1 != 0x90 {
                                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                                return
                            }
                            
                            individualNumberCard.data.signature = responseData
                            print("\n\nHERE+++++++++++++++++++")
                            print(individualNumberCard.data.signature?.hexString)
                            semaphore.signal()
                            
                        }
                    }
                }
                
            }
            
            
        }
        
        semaphore.wait()
        return individualNumberCard
    }
    
    internal func readInfo(_ session: NFCTagReaderSession, _ individualNumberCard: IndividualNumberCard, cardInfoInputSupportAppPIN: [UInt8]) -> IndividualNumberCard {
        
        if cardInfoInputSupportAppPIN.isEmpty {
            session.invalidate(errorMessage: IndividualNumberReaderError.needPIN.errorDescription!)
            self.delegate?.japanNFCReaderSession(didInvalidateWithError: IndividualNumberReaderError.needPIN)
            return individualNumberCard
        }
        
        let semaphore = DispatchSemaphore(value: 0)
        var individualNumberCard = individualNumberCard
        let tag = individualNumberCard.tag
        
        self.selectCardInfoInputSupportAP(tag: tag) { (responseData, sw1, sw2, error) in
            self.printData(responseData, sw1, sw2)
            
            if let error = error {
                print(error.localizedDescription)
                session.invalidate(errorMessage: "SELECT TextAP\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                return
            }
            
            if sw1 != 0x90 {
                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                return
            }
            
            self.selectEF(tag: tag, data: [0x00, 0x11]) { (responseData, sw1, sw2, error) in
                self.printData(responseData, sw1, sw2)
                
                if let error = error {
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    return
                }
                
                if sw1 != 0x90 {
                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    return
                }
                
                self.verify(tag: tag, pin: cardInfoInputSupportAppPIN) { (responseData, sw1, sw2, error) in
                    self.printData(responseData, sw1, sw2)
                    
                    if let error = error {
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "VERIFY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        return
                    }
                    
                    if sw1 != 0x90 {
                        if sw1 == 0x63 {
                            var error = IndividualNumberReaderError.incorrectPIN(0)
                            switch sw2 {
                            case 0xC1:
                                error = .incorrectPIN(1)
                            case 0xC2:
                                error = .incorrectPIN(2)
                            case 0xC3:
                                error = .incorrectPIN(3)
                            case 0xC4:
                                error = .incorrectPIN(4)
                            case 0xC5:
                                error = .incorrectPIN(5)
                            default:
                                break
                            }
                            print("PIN エラー", error)
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        }
                        session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                        return
                    }
                    
                    self.selectEF(tag: tag, data: [0x00, 0x02]) { (responseData, sw1, sw2, error) in
                        self.printData(responseData, sw1, sw2)
                        
                        if let error = error {
                            print(error.localizedDescription)
                            session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                            self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                            return
                        }
                        
                        if sw1 != 0x90 {
                            session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                            return
                        }
                        
                        self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: 7) { (responseData, sw1, sw2, error) in
                            self.printData(responseData, sw1, sw2)
                            
                            if let error = error {
                                print(error.localizedDescription)
                                session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                                return
                            }
                            
                            if sw1 != 0x90 {
                                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                                return
                            }
                            
                            self.printData(responseData, isPrintData: true, sw1, sw2)
                            
                            guard let asn1 = try? ASN1PartialParser(data: responseData) else {
                                session.invalidate(errorMessage: "ASN1PartialParser Error")
                                return
                            }
                            
                            self.readBinary(tag: tag, p1Parameter: 0x00, p2Parameter: 0x00, expectedResponseLength: asn1.size) { (responseData, sw1, sw2, error) in
                                self.printData(responseData, sw1, sw2)
                                
                                if let error = error {
                                    print(error.localizedDescription)
                                    session.invalidate(errorMessage: "READ BINARY\n\(error.localizedDescription)")
                                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                                    return
                                }
                                
                                if sw1 != 0x90 {
                                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                                    return
                                }
                                
                                var data = [UInt8](responseData)
//                                data.removeFirst()
//                                let fields = TLVField.sequenceOfFields(from: data)
//                                let fieldData = fields.first!.value
//                                let string = String(data: Data(fieldData), encoding: .utf8)
//
//                                var parsed: ASN1Node
//                                try! parsed = DER.parse(data)
//
//                                guard case .constructed(let children) = parsed.content else {
//                                    return
//                                }
//                                var iterator = children.makeIterator()
//                                var node_header = iterator.next()
//                                var node_name = iterator.next()
//                                guard case .primitive(let name_data) = node_name?.content else {
//                                    return
//                                }
//                                let name_string = Array(name_data).toUtf8String()
//
//                                var node_address = iterator.next()
//                                guard case .primitive(let address_data) = node_address?.content else {
//                                    return
//                                }
//                                let address_string = Array(address_data).toUtf8String()
//
//                                var node_birth = iterator.next()
//                                guard case .primitive(let birth_data) = node_birth?.content else {
//                                    return
//                                }
//                                let birth_string = Array(birth_data).toUtf8String()
//
//                                var node_sex = iterator.next()
//                                guard case .primitive(let sex_data) = node_sex?.content else {
//                                    return
//                                }
//                                let sex_index = Array(sex_data).toUtf8String()
//
//                                var sex_string = "不明"
//                                switch(sex_index){
//                                case "1":
//                                    sex_string = "男性"
//                                case "2":
//                                    sex_string = "女性"
//                                case "9":
//                                    sex_string = "適用不能"
//                                default:
//                                    sex_string = "不明"
//                                }
//
//                                individualNumberCard.data.name = name_string
//                                individualNumberCard.data.address = address_string
//                                individualNumberCard.data.birthday = birth_string
//                                individualNumberCard.data.sex = sex_string
                                individualNumberCard.data.raw = data
                                
                                semaphore.signal()
                            }
                        }
                    }
                }
            }
        }
        
        semaphore.wait()
        return individualNumberCard
    }
    
    
    internal func lookupRemainingPIN(_ session: NFCTagReaderSession, _ tag: IndividualNumberCardTag, _ pinType: IndividualNumberCardPINType) -> Int? {
        var remaining: Int? = nil
        let semaphore = DispatchSemaphore(value: 0)
        
        let dfData: Data
        let efData: [UInt8]
        switch pinType {
        case .digitalSignature:
            dfData = IndividualNumberCardAID.jpkiAP
            efData = [0x00, 0x1B]
        case .userAuthentication:
            dfData = IndividualNumberCardAID.jpkiAP
            efData = [0x00, 0x18]
        case .cardInfoInputSupport:
            dfData = IndividualNumberCardAID.cardInfoInputSupportAP
            efData = [0x00, 0x11]
        case .individualNumber:
            dfData = IndividualNumberCardAID.individualNumberAP
            efData = [0x00, 0x1C]
        }
        
        self.selectDF(tag: tag, data: dfData) { (responseData, sw1, sw2, error) in
            // self.printData(responseData, isPrintData: true, sw1, sw2)
            
            if let error = error {
                print(error.localizedDescription)
                session.invalidate(errorMessage: "SELECT DF\n\(error.localizedDescription)")
                self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                semaphore.signal()
                return
            }
            
            if sw1 != 0x90 {
                session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                semaphore.signal()
                return
            }
            
            self.selectEF(tag: tag, data: efData) { (responseData, sw1, sw2, error) in
                // self.printData(responseData, isPrintData: true, sw1, sw2)
                
                if let error = error {
                    print(error.localizedDescription)
                    session.invalidate(errorMessage: "SELECT EF\n\(error.localizedDescription)")
                    self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                    semaphore.signal()
                    return
                }
                
                if sw1 != 0x90 {
                    session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    semaphore.signal()
                    return
                }
                
                self.verify(tag: tag, pin: []) { (responseData, sw1, sw2, error) in
                    // self.printData(responseData, isPrintData: true, sw1, sw2)
                    
                    if let error = error {
                        print(error.localizedDescription)
                        session.invalidate(errorMessage: "VERIFY\n\(error.localizedDescription)")
                        self.delegate?.japanNFCReaderSession(didInvalidateWithError: error)
                        semaphore.signal()
                        return
                    }
                    
                    if sw1 == 0x63 {
                        remaining = Int(sw2 & 0x0F)
                    } else {
                        session.invalidate(errorMessage: "エラー: ステータス: \(ISO7816Status.localizedString(forStatusCode: sw1, sw2))")
                    }
                    
                    semaphore.signal()
                }
            }
        }
        
        semaphore.wait()
        return remaining
    }
}

#endif
