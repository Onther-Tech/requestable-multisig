pragma solidity ^0.4.24;

import "./RLP.sol";
import "./SimpleDecode.sol";


// orignated from https://github.com/gnosis/MultiSigWallet/blob/master/contracts/MultiSigWallet.sol
// solium-disable function-order
contract RequestableMultisig {
  using SimpleDecode for bytes;

  /*
   *  Events
   */
  event Confirmation(address indexed sender, bytes32 indexed transactionId);
  event Revocation(address indexed sender, bytes32 indexed transactionId);
  event Submission(bytes32 indexed transactionId);
  event Execution(bytes32 indexed transactionId);
  event ExecutionFailure(bytes32 indexed transactionId);
  event ExecutionAdded(bytes32 indexed transactionId);
  event Deposit(address indexed sender, uint value);
  event OwnerAddition(address indexed owner);
  event OwnerRemoval(address indexed owner);
  event RequirementChange(uint required);

  /*
   *  Constants
   */
  // Smaller than original implementation to prevent out-of-gas erorr in request transaction,
  uint constant public MAX_OWNER_COUNT = 16;

  /*
   *  Storage
   */
  // rootchain is not requestable.
  address public rootchain;

  // Request for transaction has trieKey of 0x00.
  mapping (bytes32 => Transaction) public transactions;

  // Request for transactionIds has trieKey of 0x01.
  bytes32[] public transactionIds;

  // Request for executed has trieKey of 0x02.
  mapping (bytes32 => bool) public executed;

  // Request for new confirmation has trieKey of 0x03.
  // Request for revoked confirmation has trieKey of 0x04.
  mapping (bytes32 => mapping (address => bool)) public confirmations;

  // Request for new owner has trieKey of 0x05.
  // Request for removed owner has trieKey of 0x06.
  address[] public owners;
  mapping (address => bool) public isOwner;

  // Request for required has trieKey of 0x07.
  uint public required;

  // appliedRequests is not requestable.
  mapping(uint => bool) appliedRequests;

  struct Transaction {
    address destination;
    uint value;
    bytes data;
    bool added; // Whether transaction is added or not
  }

  /*
   *  Modifiers
   */
  modifier onlyWallet() {
    require(msg.sender == address(this));
    _;
  }

  modifier ownerDoesNotExist(address owner) {
    require(!isOwner[owner]);
    _;
  }

  modifier ownerExists(address owner) {
    require(isOwner[owner]);
    _;
  }

  modifier transactionExists(bytes32 transactionId) {
    require(transactions[transactionId].destination != 0);
    _;
  }

  modifier transactionNotEmpty(bytes32 transactionId) {
    require(!isEmpty(transactionId));
    _;
  }

  modifier confirmed(bytes32 transactionId, address owner) {
    require(confirmations[transactionId][owner]);
    _;
  }

  modifier notConfirmed(bytes32 transactionId, address owner) {
    require(!confirmations[transactionId][owner]);
    _;
  }

  modifier notExecuted(bytes32 transactionId) {
    require(!executed[transactionId]);
    _;
  }

  modifier notNull(address _address) {
    require(_address != 0);
    _;
  }

  modifier validRequirement(uint ownerCount, uint _required) {
    require(ownerCount <= MAX_OWNER_COUNT && // solium-disable-line
      _required <= ownerCount &&
      _required != 0 &&
      ownerCount != 0);
    _;
  }
  /*
   * Constructor
   */
  /// @dev Contract constructor sets initial owners and required number of confirmations.
  /// @param _rootchain RootChain contract address.
  /// @param _owners List of initial owners.
  /// @param _required Number of required confirmations.
  constructor(address _rootchain, address[] _owners, uint _required)
    public
    notNull(_rootchain)
    validRequirement(_owners.length, _required)
  {
    for (uint i = 0; i < _owners.length; i++) {
      require(!isOwner[_owners[i]] && _owners[i] != 0);
      isOwner[_owners[i]] = true;
    }

    rootchain = _rootchain;
    owners = _owners;
    required = _required;
  }

  /// @dev Fallback function allows to deposit ether.
  function () external payable {
    if (msg.value > 0) {
      emit Deposit(msg.sender, msg.value);
    }
  }

  /*
   * Requestable functions
   */
  /// @dev Apply request in root chain.
  /// @param isExit Whether the request is exit or not.
  /// @param requestId Id of request.
  /// @param requestor Address who made request.
  /// @param trieKey Key of request.
  /// @param trieValue Value of request.
  function applyRequestInRootChain(
    bool isExit,
    uint256 requestId,
    address requestor,
    bytes32 trieKey,
    bytes trieValue
  ) public returns (bool success) {
    require(msg.sender == rootchain);
    _handle(true, isExit, requestId, requestor, trieKey, trieValue); // solium-disable-line arg-overflow
  }

  /// @dev Apply request in child chain.
  /// @param isExit Whether the request is exit or not.
  /// @param requestId Id of request.
  /// @param requestor Address who made request.
  /// @param trieKey Key of request.
  /// @param trieValue Value of request.
  function applyRequestInChildChain(
    bool isExit,
    uint256 requestId,
    address requestor,
    bytes32 trieKey,
    bytes trieValue
  ) public returns (bool success) {
    require(msg.sender == address(0));
    _handle(false, isExit, requestId, requestor, trieKey, trieValue); // solium-disable-line arg-overflow
  }

  /// @dev A helper for applyRequestIn*Chain fuction.
  ///      Request for transactionId, executed, confirmation, and owner has trie value with size of 32 bytes.
  /// @param isExit Whether the request is exit or not.
  /// @param requestId Id of request.
  /// @param requestor Address who made request.
  /// @param trieKey Key of request.
  /// @param trieValue Value of request.
  function _handle(
    bool isRootChain,
    bool isExit,
    uint256 requestId,
    address requestor,
    bytes32 trieKey,
    bytes trieValue
  ) internal {
    require(!appliedRequests[requestId]);

    if (trieKey == 0x00) {
      _handleTransaction(isRootChain, isExit, toTransaction(trieValue));
    } else if (trieKey == 0x01) {
      _handleTransactionId(isExit, trieValue.toBytes32());
    } else if (trieKey == bytes32(0x02)) {
      _handleExecuted(isExit, trieValue.toBytes32());
    } else if (trieKey == bytes32(0x03)) {
      _handleNewConfirmation(isRootChain, isExit, requestor, trieValue.toBytes32()); // solium-disable-line arg-overflow
    } else if (trieKey == bytes32(0x04)) {
      _handleRevokedConfirmation(isRootChain, isExit, requestor, trieValue.toBytes32()); // solium-disable-line arg-overflow
    } else if (trieKey == bytes32(0x05)) {
      _handleNewOwner(isExit, trieValue.toAddress());
    } else if (trieKey == bytes32(0x06)) {
      _handleRemovedOwner(isExit, trieValue.toAddress());
    } else if (trieKey == bytes32(0x07)) {
      required = trieValue.toUint();
      emit RequirementChange(trieValue.toUint());
    } else {
      revert();
    }

    appliedRequests[requestId] = true;
  }

  function _handleTransaction(bool isRootChain, bool isExit, Transaction memory transaction) internal {
    bytes32 transactionId = hash(transaction);

    // transaction check
    //                          isRootChain == true       isRootChain == false
    //                       +--------------------------------------------------
    //     enter request     |  must be added         |  must not be added
    //     exit request      |  must not be added     |  must be added

    if (isRootChain && !isExit || !isRootChain && isExit) {
      require(transactions[transactionId].added);
    } else {
      require(!transactions[transactionId].added);
      addTransaction(transaction.destination, transaction.value, transaction.data);
    }
  }

  function _handleTransactionId(bool isExit, bytes32 transactionId) internal {
    Transaction storage transaction = transactions[transactionId];

    // short circuit if transaction is already included for exit request.
    require(!isExit || !transaction.added);

    transaction.added = true;
  }

  function _handleExecuted(bool isExit, bytes32 transactionId)
    internal
  {
    // short circuit if transaction is already executed for exit request.
    require(!isExit || !executed[transactionId]);
    executed[transactionId] = true;
    emit ExecutionAdded(transactionId);
  }

  /// @notice Make sure that requestor is owner before making exit request for confirmation.
  function _handleNewConfirmation(
    bool isRootChain,
    bool isExit,
    address requestor,
    bytes32 transactionId
  )
    internal
    notExecuted(transactionId)
  {
    // check ownership for exit request.
    require(!isExit || isOwner[requestor]);

    // confirmation check
    //                          isRootChain == true       isRootChain == false
    //                       +--------------------------------------------------
    //     enter request     |  must be confirmed      |  must not be confirmed
    //     exit request      |  must not be confirmed  |  must be confirmed
    if (isRootChain && !isExit || !isRootChain && isExit) {
      require(confirmations[transactionId][requestor]);
      confirmations[transactionId][requestor] = false;
      // What evnet should be fired?
    } else {
      require(!confirmations[transactionId][requestor]);
      confirmations[transactionId][requestor] = true;
      emit Confirmation(requestor, transactionId);
    }
  }

  /// @notice Make sure that requestor is owner before making exit request for confirmation.
  function _handleRevokedConfirmation(
    bool isRootChain,
    bool isExit,
    address requestor,
    bytes32 transactionId
  )
    internal
    notExecuted(transactionId)
  {
    // check ownership for exit request.
    require(!isExit || isOwner[requestor]);

    // confirmation check
    //                          isRootChain == true       isRootChain == false
    //                       +--------------------------------------------------
    //     enter request     |  must be not confirmed  |  must be confirmed
    //     exit request      |  must be confirmed      |  must not be confirmed
    if (isRootChain && !isExit || !isRootChain && isExit) {
      require(!confirmations[transactionId][requestor]);
      // What evnet should be fired?
    } else {
      require(confirmations[transactionId][requestor]);
      confirmations[transactionId][requestor] = false;
      emit Revocation(requestor, transactionId);
    }
  }

  function _handleNewOwner(bool isExit, address owner) internal {
    // check ownership for exit request.
    require(!isExit || !isOwner[owner]);

    // short circuit if owner is null for exit request.
    require(!isExit || owner != address(0));

    if (!isOwner[owner]) {
      this.addOwner(owner);
    }
  }

  function _handleRemovedOwner(bool isExit, address owner) internal {
    // check ownership for exit request.
    require(!isExit || isOwner[owner]);

    if (isOwner[owner]) {
      this.removeOwner(owner);
    }
  }

  function toTransaction(bytes memory b) internal pure returns (Transaction memory transaction) {
    RLP.RLPItem[] memory items = b.toRlpItem().toList();

    transaction.destination = items[0].toAddress();
    transaction.value = items[1].toUint();
    transaction.data = items[2].toBytes();
    transaction.added = true;
  }

  /*
   * Public functions
   */

  /// @dev Allows to add a new owner. Transaction has to be sent by wallet.
  /// @param owner Address of new owner.
  function addOwner(address owner)
    public
    onlyWallet
    ownerDoesNotExist(owner)
    notNull(owner)
    validRequirement(owners.length + 1, required)
  {
    isOwner[owner] = true;
    owners.push(owner);
    emit OwnerAddition(owner);
  }

  /// @dev Allows to remove an owner. Transaction has to be sent by wallet.
  /// @param owner Address of owner.
  function removeOwner(address owner)
    public
    onlyWallet
    ownerExists(owner)
  {
    isOwner[owner] = false;
    for (uint i = 0; i < owners.length - 1; i++) {
      if (owners[i] == owner) {
        owners[i] = owners[owners.length - 1];
        break;
      }
    }

    owners.length -= 1;
    if (required > owners.length) {
      changeRequirement(owners.length);
    }
    emit OwnerRemoval(owner);
  }

  /// @dev Allows to replace an owner with a new owner. Transaction has to be sent by wallet.
  /// @param owner Address of owner to be replaced.
  /// @param newOwner Address of new owner.
  function replaceOwner(address owner, address newOwner)
    public
    onlyWallet
    ownerExists(owner)
    ownerDoesNotExist(newOwner)
  {
    for (uint i = 0; i < owners.length; i++) {
      if (owners[i] == owner) {
        owners[i] = newOwner;
        break;
      }
    }

    isOwner[owner] = false;
    isOwner[newOwner] = true;

    emit OwnerRemoval(owner);
    emit OwnerAddition(newOwner);
  }

  /// @dev Allows to change the number of required confirmations. Transaction has to be sent by wallet.
  /// @param _required Number of required confirmations.
  function changeRequirement(uint _required)
    public
    onlyWallet
    validRequirement(owners.length, _required)
  {
    required = _required;
    emit RequirementChange(_required);
  }

  /// @dev Allows an owner to submit and confirm a transaction.
  /// @param destination Transaction target address.
  /// @param value Transaction ether value.
  /// @param data Transaction data payload.
  /// @return Returns transaction ID.
  function submitTransaction(address destination, uint value, bytes data)
    public
    returns (bytes32 transactionId)
  {
    transactionId = addTransaction(destination, value, data);
    confirmTransaction(transactionId);
  }

  /// @dev Allows an owner to confirm a transaction.
  /// @param transactionId Transaction ID.
  function confirmTransaction(bytes32 transactionId)
    public
    ownerExists(msg.sender)
    transactionExists(transactionId)
    notConfirmed(transactionId, msg.sender)
  {
    confirmations[transactionId][msg.sender] = true;
    emit Confirmation(msg.sender, transactionId);

    if (!isEmpty(transactionId)) {
      executeTransaction(transactionId);
    }
  }

  /// @dev Allows an owner to revoke a confirmation for a transaction.
  /// @param transactionId Transaction ID.
  function revokeConfirmation(bytes32 transactionId)
    public
    ownerExists(msg.sender)
    confirmed(transactionId, msg.sender)
    notExecuted(transactionId)
  {
    confirmations[transactionId][msg.sender] = false;
    emit Revocation(msg.sender, transactionId);
  }

  /// @dev Allows anyone to execute a confirmed transaction.
  /// @param transactionId Transaction ID.
  function executeTransaction(bytes32 transactionId)
    public
    ownerExists(msg.sender)
    confirmed(transactionId, msg.sender)
    notExecuted(transactionId)
    transactionNotEmpty(transactionId)
  {
    if (isConfirmed(transactionId)) {
      Transaction storage txn = transactions[transactionId];
      executed[hash(txn)] = true;

      if (external_call(txn.destination, txn.value, txn.data.length, txn.data)) {
        emit Execution(transactionId);
      } else {
        emit ExecutionFailure(transactionId);
        executed[hash(txn)] = false;
      }
    }
  }

  // call has been separated into its own function in order to take advantage
  // of the Solidity's code generator to produce a loop that copies tx.data into memory.
  function external_call(address destination, uint value, uint dataLength, bytes data) private returns (bool) {
    bool result;
    assembly {
      let x := mload(0x40)   // "Allocate" memory for output (0x40 is where "free memory" pointer is stored by convention)
      let d := add(data, 32) // First 32 bytes are the padded length of data, so exclude that
      result := call(
        sub(gas, 34710),    // 34710 is the value that solidity is currently emitting
                            // It includes callGas (700) + callVeryLow (3, to pay for SUB) + callValueTransferGas (9000) +
                            // callNewAccountGas (25000, in case the destination address does not exist and needs creating)
        destination,
        value,
        d,
        dataLength,         // Size of the input (in bytes) - this is what fixes the padding problem
        x,
        0                   // Output is ignored, therefore the output size is zero
      )
    }
    return result;
  }

  /// @dev Returns the confirmation status of a transaction.
  /// @param transactionId Transaction ID.
  /// @return Confirmation status.
  function isConfirmed(bytes32 transactionId)
    public
    view
    returns (bool)
  {
    uint count = 0;
    for (uint i = 0; i < owners.length; i++) {
      if (confirmations[transactionId][owners[i]]) {
        count += 1;
      }

      if (count == required) {
        return true;
      }
    }
  }

  /*
   * Internal functions
   */
  /// @dev Adds a new transaction to the transaction mapping, if transaction does not exist yet.
  /// @param destination Transaction target address.
  /// @param value Transaction ether value.
  /// @param data Transaction data payload.
  /// @return Returns transaction ID.
  function addTransaction(address destination, uint value, bytes data)
    internal
    notNull(destination)
    returns (bytes32 transactionId)
  {
    Transaction memory transaction = Transaction({
      destination: destination,
      value: value,
      data: data,
      added: true
    });

    transactionId = hash(transaction);
    transactions[transactionId] = transaction;
    transactionIds.push(transactionId);

    emit Submission(transactionId);
  }

  /*
    * Web3 call functions
    */
  /// @dev Returns number of confirmations of a transaction.
  /// @param transactionId Transaction ID.
  /// @return Number of confirmations.
  function getConfirmationCount(bytes32 transactionId)
    public
    view
    returns (uint count)
  {
    for (uint i = 0; i < owners.length; i++) {
      if (confirmations[transactionId][owners[i]]) {
        count += 1;
      }
    }
  }

  /// @notice It doesn't count transactions that is not yet requested.
  /// @dev Returns total number of transactions after filers are applied.
  /// @param _pending Include pending transactions.
  /// @param _executed Include executed transactions.
  /// @return Total number of transactions after filters are applied.
  function getTransactionCount(bool _pending, bool _executed)
    public
    view
    returns (uint count)
  {
    for (uint i = 0; i < transactionIds.length; i++) {
      if (_pending && !executed[transactionIds[i]] ||
        _executed && executed[transactionIds[i]]) {
        count += 1;
      }
    }
  }

  /// @dev Returns list of owners.
  /// @return List of owner addresses.
  function getOwners()
    public
    view
    returns (address[])
  {
    return owners;
  }

  /// @dev Returns array with owner addresses, which confirmed transaction.
  /// @param transactionId Transaction ID.
  /// @return Returns array of owner addresses.
  function getConfirmations(bytes32 transactionId)
    public
    view
    returns (address[] _confirmations)
  {
    address[] memory confirmationsTemp = new address[](owners.length);
    uint count = 0;
    uint i;

    for (i = 0; i < owners.length; i++) {
      if (confirmations[transactionId][owners[i]]) {
        confirmationsTemp[count] = owners[i];
        count += 1;
      }
    }

    _confirmations = new address[](count);

    for (i = 0; i < count; i++) {
      _confirmations[i] = confirmationsTemp[i];
    }
  }

  /// @notice It may returns different result for each chains wrt data and order.
  /// @dev Returns list of transaction IDs in defined range.
  /// @param from Index start position of transaction array.
  /// @param to Index end position of transaction array.
  /// @param _pending Include pending transactions.
  /// @param _executed Include executed transactions.
  /// @return Returns array of transaction IDs.
  function getTransactionIds(uint from, uint to, bool _pending, bool _executed) // solium-disable-line arg-overflow
    public
    view
    returns (uint[] _transactionIds)
  {
    uint[] memory transactionIdsTemp = new uint[](transactionIds.length);
    uint count = 0;
    uint i;

    for (i = 0; i < transactionIds.length; i++) {
      if (_pending && !executed[transactionIds[i]] ||
        _executed && executed[transactionIds[i]]) {
        transactionIdsTemp[count] = i;
        count += 1;
      }
    }

    _transactionIds = new uint[](to - from);

    for (i = from; i < to; i++) {
      _transactionIds[i - from] = transactionIdsTemp[i];
    }
  }

  function hash(Transaction memory transaction) internal pure returns (bytes32 transactionId) {
    return keccak256(abi.encodePacked(transaction.destination, transaction.value, transaction.data));
  }

  function isEmpty(bytes32 transactionId) internal view returns (bool) {
    Transaction storage transaction = transactions[transactionId];

    return transaction.destination == address(0) && transaction.value == 0 && transaction.data.length == 0;
  }
}
