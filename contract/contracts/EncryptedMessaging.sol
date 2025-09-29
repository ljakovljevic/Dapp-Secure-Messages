// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EncryptedMessaging — on-chain metadata for end-to-end cipher messages
/// @notice Message and symmetric key are in IPFS; on-chain are CID/reference, hash and integrity control/spam.
contract EncryptedMessaging {
    // ====== Tipovi ======
    struct MessageMeta {
        uint256 id;                
        address sender;            
        address recipient;         
        uint64 timestamp;          
        bytes32 sha256Hash;        
        bytes12 iv;                
        bytes32 contentCidHash;    
        bytes32 keyCidHash;        
        uint128 nonce;             
        // (R,S,V) ECDSA metadata signature (optional, may be null)
        bytes32 sigR;
        bytes32 sigS;
        uint8   sigV;
    }

    struct KeyRecord {
        bytes32 rsaPubKeySha256;   
        string  rsaPubKeyURI;     
        uint64  updatedAt;
    }

    // ====== Storage ======
    uint256 public nextMessageId = 1;

    
    mapping(uint256 => MessageMeta) public messages;

    
    mapping(address => uint256[]) private inboxIndex;

    
    mapping(address => uint256[]) private outboxIndex;

    
    mapping(address => uint128) public lastNonce;

    
    uint64 public minIntervalSeconds = 10;

    
    mapping(address => uint64) public lastSentAt;

    
    mapping(address => mapping(address => mapping(bytes12 => bool))) public usedIV;

    
    mapping(address => KeyRecord) public keyRegistry;

    // ====== Events ======
    event MessageSent(
        uint256 indexed id,
        address indexed sender,
        address indexed recipient,
        uint64 timestamp,
        bytes32 sha256Hash,
        bytes12 iv,
        bytes32 contentCidHash,
        bytes32 keyCidHash,
        uint128 nonce
    );

    event KeyRegistered(
        address indexed owner,
        bytes32 rsaPubKeySha256,
        string rsaPubKeyURI,
        uint64 updatedAt
    );

    event MinIntervalUpdated(uint64 newValue);

    function setMinInterval(uint64 newValue) external {
        minIntervalSeconds = newValue;
        emit MinIntervalUpdated(newValue);
    }

    // ====== Key Registry ======
    /// @notice Register/change fingerprint or URI of yours RSA public key (for clients which texting you).
    function registerRSAPublicKey(bytes32 rsaPubKeySha256, string calldata rsaPubKeyURI) external {
        keyRegistry[msg.sender] = KeyRecord({
            rsaPubKeySha256: rsaPubKeySha256,
            rsaPubKeyURI: rsaPubKeyURI,
            updatedAt: uint64(block.timestamp)
        });
        emit KeyRegistered(msg.sender, rsaPubKeySha256, rsaPubKeyURI, uint64(block.timestamp));
    }

    // ====== Message sending (metadata) ======
    /// @param recipient receiver
    /// @param contentCID IPFS CID for encrypted content (JSON/blob), off-chain
    /// @param keyCID IPFS CID for RSA-encrypted data-key for *this* receiver
    /// @param sha256Hash SHA-256 fingerprint (bytes32) on *agreed* payload (recommendation: ciphertext)
    /// @param iv 96-bit AES-GCM IV (required and *unique* for that key)
    /// @param nonce monoton for msg.sender (must be lastNonce+1)
    /// @param sigV  V component of ECDSA signature on commitment hash 
    /// @param sigR  R component of ECDSA signature
    /// @param sigS  S component of ECDSA signature.
    function sendMessage(
        address recipient,
        string calldata contentCID,
        string calldata keyCID,
        bytes32 sha256Hash,
        bytes12 iv,
        uint128 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        require(recipient != address(0), "recipient=0");
        require(sha256Hash != bytes32(0), "sha256Hash=0");
        require(iv != bytes12(0), "iv=0");

        // Rate limit
        uint64 nowTs = uint64(block.timestamp);
        uint64 lastTs = lastSentAt[msg.sender];
        require(nowTs - lastTs >= minIntervalSeconds, "rate-limited");
        lastSentAt[msg.sender] = nowTs;

        // Unique IV per (sender, recipient)
        require(!usedIV[msg.sender][recipient][iv], "IV already used");
        usedIV[msg.sender][recipient][iv] = true;

        // Anti-replay nonce
        require(nonce == lastNonce[msg.sender] + 1, "bad nonce");
        lastNonce[msg.sender] = nonce;

        // Hash CIDs (cheaper storage)
        bytes32 contentCidHash = keccak256(bytes(contentCID));
        bytes32 keyCidHash = keccak256(bytes(keyCID));

        // ECDSA verification of metadata signature.
        // If sigV==0 and R/S==0 -> skip verification (“no signature” mode)
        if (sigV != 0 || sigR != bytes32(0) || sigS != bytes32(0)) {
            // Define stict “commitment” on metadata (keccak256)
            // Sign standard Ethereum Signed Message (EIP-191).
            bytes32 commit = keccak256(
                abi.encodePacked(
                    bytes1(0x19),
                    bytes1(0x45), // 'E'
                    "MSG:",
                    msg.sender,
                    recipient,
                    nowTs,
                    sha256Hash,
                    iv,
                    contentCidHash,
                    keyCidHash,
                    nonce
                )
            );
            bytes32 ethMsgHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", commit)
            );
            address recovered = ecrecover(ethMsgHash, sigV, sigR, sigS);
            require(recovered == msg.sender, "bad signature");
        }

        uint256 id = nextMessageId++;
        messages[id] = MessageMeta({
            id: id,
            sender: msg.sender,
            recipient: recipient,
            timestamp: nowTs,
            sha256Hash: sha256Hash,
            iv: iv,
            contentCidHash: contentCidHash,
            keyCidHash: keyCidHash,
            nonce: nonce,
            sigR: sigR,
            sigS: sigS,
            sigV: sigV
        });

        inboxIndex[recipient].push(id);
        outboxIndex[msg.sender].push(id);

        emit MessageSent(
            id,
            msg.sender,
            recipient,
            nowTs,
            sha256Hash,
            iv,
            contentCidHash,
            keyCidHash,
            nonce
        );
    }

    // ====== Getters ======
    function getInboxIds(address user) external view returns (uint256[] memory) {
        return inboxIndex[user];
    }

    function getOutboxIds(address user) external view returns (uint256[] memory) {
        return outboxIndex[user];
    }

    // Check if specific IV is already used between A i B
    function isIVUsed(address sender_, address recipient_, bytes12 iv_) external view returns (bool) {
        return usedIV[sender_][recipient_][iv_];
    }
}