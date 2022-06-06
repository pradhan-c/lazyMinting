//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract LazyNFT is ERC721URIStorage, EIP712, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string private constant SIGNING_DOMAIN = "LazyNFT-Voucher";
    string private constant SIGNATURE_VERSION = "1";

    uint256 public totalminted;
    address private signer;

    mapping(uint256 => bool) private mintedById;

    //event for off-chain purchase
    event RedeemedAndMinted(
        address indexed signer,
        address minter,
        uint256 tokenId,
        uint256 minPrice,
        string tokenURI,
        string name,
        string description,
        bytes signature
    );

    event Bought(
        uint256 itemId,
        bool sold,
        uint256 price,
        address indexed seller,
        address indexed buyer
    );

    constructor()
        ERC721("LazyMINT", "LAZY")
        EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION)
    {}

    function setMinter(address _signer) internal {
        signer = _signer;
        _setupRole(MINTER_ROLE, signer);
    }

    function getMinter() public view returns (address) {
        return signer;
    }

    function getTotalMinted() public view returns (uint256) {
        return totalminted;
    }

    /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
    /// @param redeemer The address of the account which will receive the NFT upon success.
    function redeem(
        address redeemer,
        uint256 tokenId,
        uint256 minPrice,
        string memory uri,
        string memory name,
        string memory description,
        bytes memory signature
    ) public payable {
        require(minPrice > 0, "Price must be greater than zero");
        // make sure signature is valid and get the address of the signer
        signer = _verify(tokenId, minPrice, uri, name, description, signature);

        // set the minter address in _setupRole
        setMinter(signer);

        //make sure owner cant buy his own nft
        require(signer != msg.sender, "You cant buy your own NFT");

        // make sure that the signer is authorized to mint NFTs
        require(
            hasRole(MINTER_ROLE, signer),
            "Signature invalid or unauthorized"
        );

        // make sure that the redeemer is paying enough to cover the buyer's cost
        require(msg.value >= minPrice, "Insufficient funds to redeem");

        // first assign the token to the signer, to establish provenance on-chain
        _mint(signer, tokenId);
        _setTokenURI(tokenId, uri);

        _transfer(signer, redeemer, tokenId);
        mintedById[tokenId] = true;

        emit RedeemedAndMinted(
            signer,
            redeemer,
            tokenId,
            minPrice,
            uri,
            name,
            description,
            signature
        );

        totalminted = totalminted + 1;

        // send amount to the signer
        (bool sent, ) = payable(signer).call{value: msg.value}("");
        require(sent, "Failed to send Ether");
    }

    function purchaseItem(
        uint256 _itemId,
        uint256 price,
        address owner
    ) external payable {
        require(msg.value > 0, "Price must be greater than zero");
        _transfer(owner, msg.sender, _itemId);
        // send amount to the signer
        (bool sent, ) = payable(owner).call{value: msg.value}("");
        require(sent, "Failed to send Ether");

        // emit Bought event
        emit Bought(_itemId, true, price, owner, msg.sender);
    }

    /// @notice Verifies the signature for a given voucher data, returning the address of the signer.
    /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
    function _verify(
        uint256 tokenId,
        uint256 minPrice,
        string memory uri,
        string memory name,
        string memory description,
        bytes memory signature
    ) public view returns (address) {
        bytes32 digest = _hash(tokenId, minPrice, name, description, uri);
        return ECDSA.recover(digest, signature);
    }

    /// @notice Returns a hash of the given data, prepared using EIP712 typed data hashing rules.
    /// @param  tokenId for id of token
    ///@param minPrice price of nft
    ///@param uri metadata of the token
    function _hash(
        uint256 tokenId,
        uint256 minPrice,
        string memory name,
        string memory description,
        string memory uri
    ) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "NFTVoucher(uint256 tokenId,uint256 minPrice,string name,string description,string uri)"
                        ),
                        tokenId,
                        minPrice,
                        keccak256(bytes(name)),
                        keccak256(bytes(description)),
                        keccak256(bytes(uri))
                    )
                )
            );
    }

    /// @notice Returns the chain id of the current blockchain.
    function getChainID() external view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControl, ERC721)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
