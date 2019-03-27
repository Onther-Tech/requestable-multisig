pragma solidity ^0.4.24;


library SimpleDecode {
  function toUint(bytes memory b) internal pure returns (uint v) {
    require(b.length == 0x20);

    assembly {
      v := mload(add(b, 0x20))
    }
  }

  function toBytes32(bytes memory b) internal pure returns (bytes32 v) {
    return bytes32(toUint(b));
  }

  function toAddress(bytes memory b) internal pure returns (address v) {
    return address(toBytes32(b));
  }
}