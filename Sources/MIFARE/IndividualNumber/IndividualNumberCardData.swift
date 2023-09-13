//
//  IndividualNumberCardData.swift
//  TRETJapanNFCReader
//
//  Created by treastrain on 2020/05/11.
//  Copyright © 2020 treastrain / Tanaka Ryoga. All rights reserved.
//

import Foundation

/// マイナンバーカードのデータ
public struct IndividualNumberCardData {
    /// トークン情報
    public var token: String?
    /// マイナンバー
    public var individualNumber: String?
    
    /// name
    public var name: String?
    /// address
    public var address: String?
    ///  birthday
    public var birthday: String?
    ///  sex
    public var sex: String?
    
    /// certificate
    public var certificate_pem: String?
    public var certificate_pem_before: Data?
    
    /// signature
    public var signature: Data?
    
    /// raw
    public var raw: [UInt8]?
}
