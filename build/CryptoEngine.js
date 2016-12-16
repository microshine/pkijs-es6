"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _PublicKeyInfo = require("./PublicKeyInfo");

var _PublicKeyInfo2 = _interopRequireDefault(_PublicKeyInfo);

var _PrivateKeyInfo = require("./PrivateKeyInfo");

var _PrivateKeyInfo2 = _interopRequireDefault(_PrivateKeyInfo);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CryptoEngine = function () {
	//**********************************************************************************
	/**
  * Constructor for CryptoEngine class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CryptoEngine() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CryptoEngine);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description Usually here we are expecting "window.crypto.subtle" or an equivalent from custom "crypto engine"
   */
		this.crypto = (0, _pvutils.getParametersValue)(parameters, "crypto", {});

		/**
   * @type {string}
   * @description Name of the "crypto engine"
   */
		this.name = (0, _pvutils.getParametersValue)(parameters, "name", "");
		//endregion
	}
	//**********************************************************************************
	/**
  * Import WebCrypto keys from different formats
  * @param {string} format
  * @param {ArrayBuffer|Object} keyData
  * @param {Object} algorithm
  * @param {boolean} extractable
  * @param {Array} keyUsages
  * @returns {Promise}
  */


	_createClass(CryptoEngine, [{
		key: "importKey",
		value: function importKey(format, keyData, algorithm, extractable, keyUsages) {
			//region Initial variables
			var jwk = {};
			//endregion

			//region Change "keyData" type if needed
			if (keyData instanceof Uint8Array) keyData = keyData.buffer;
			//endregion

			switch (format.toLowerCase()) {
				case "raw":
					return this.crypto.importKey("raw", keyData, algorithm, extractable, keyUsages);
				case "spki":
					{
						var asn1 = asn1js.fromBER(keyData);
						if (asn1.offset === -1) return Promise.reject("Incorrect keyData");

						var publicKeyInfo = new _PublicKeyInfo2.default();
						try {
							publicKeyInfo.fromSchema(asn1.result);
						} catch (ex) {
							return Promise.reject("Incorrect keyData");
						}

						switch (algorithm.name.toUpperCase()) {
							case "RSA-PSS":
								{
									//region Get information about used hash function
									switch (algorithm.hash.name.toUpperCase()) {
										case "SHA-1":
											jwk.alg = "PS1";
											break;
										case "SHA-256":
											jwk.alg = "PS256";
											break;
										case "SHA-384":
											jwk.alg = "PS384";
											break;
										case "SHA-512":
											jwk.alg = "PS512";
											break;
										default:
											return Promise.reject("Incorrect hash algorithm: " + algorithm.hash.name.toUpperCase());
									}
									//endregion
								}
							case "RSASSA-PKCS1-V1_5":
								{
									keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key

									jwk.kty = "RSA";
									jwk.ext = extractable;
									jwk.key_ops = keyUsages;

									if (publicKeyInfo.algorithm.algorithmId !== "1.2.840.113549.1.1.1") return Promise.reject("Incorrect public key algorithm: " + publicKeyInfo.algorithm.algorithmId);

									//region Get information about used hash function
									if ("alg" in jwk === false) {
										switch (algorithm.hash.name.toUpperCase()) {
											case "SHA-1":
												jwk.alg = "RS1";
												break;
											case "SHA-256":
												jwk.alg = "RS256";
												break;
											case "SHA-384":
												jwk.alg = "RS384";
												break;
											case "SHA-512":
												jwk.alg = "RS512";
												break;
											default:
												return Promise.reject("Incorrect public key algorithm: " + publicKeyInfo.algorithm.algorithmId);
										}
									}
									//endregion

									//region Create RSA Public Key elements
									var publicKeyJSON = publicKeyInfo.toJSON();

									var _iteratorNormalCompletion = true;
									var _didIteratorError = false;
									var _iteratorError = undefined;

									try {
										for (var _iterator = Object.keys(publicKeyJSON)[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
											var key = _step.value;

											jwk[key] = publicKeyJSON[key];
										} //endregion
									} catch (err) {
										_didIteratorError = true;
										_iteratorError = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion && _iterator.return) {
												_iterator.return();
											}
										} finally {
											if (_didIteratorError) {
												throw _iteratorError;
											}
										}
									}
								}
								break;
							case "ECDSA":
								keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key
							case "ECDH":
								{
									//region Initial variables
									jwk = {
										kty: "EC",
										ext: extractable,
										key_ops: keyUsages
									};
									//endregion

									//region Get information about algorithm
									if (publicKeyInfo.algorithm.algorithmId !== "1.2.840.10045.2.1") return Promise.reject("Incorrect public key algorithm: " + publicKeyInfo.algorithm.algorithmId);
									//endregion

									//region Create ECDSA Public Key elements
									var _publicKeyJSON = publicKeyInfo.toJSON();

									var _iteratorNormalCompletion2 = true;
									var _didIteratorError2 = false;
									var _iteratorError2 = undefined;

									try {
										for (var _iterator2 = Object.keys(_publicKeyJSON)[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
											var _key = _step2.value;

											jwk[_key] = _publicKeyJSON[_key];
										} //endregion
									} catch (err) {
										_didIteratorError2 = true;
										_iteratorError2 = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion2 && _iterator2.return) {
												_iterator2.return();
											}
										} finally {
											if (_didIteratorError2) {
												throw _iteratorError2;
											}
										}
									}
								}
								break;
							case "RSA-OAEP":
								{
									jwk.kty = "RSA";
									jwk.ext = extractable;
									jwk.key_ops = keyUsages;

									if (this.name.toLowerCase() === "safari") jwk.alg = "RSA-OAEP";else {
										switch (algorithm.hash.name.toUpperCase()) {
											case "SHA-1":
												jwk.alg = "RSA-OAEP-1";
												break;
											case "SHA-256":
												jwk.alg = "RSA-OAEP-256";
												break;
											case "SHA-384":
												jwk.alg = "RSA-OAEP-384";
												break;
											case "SHA-512":
												jwk.alg = "RSA-OAEP-512";
												break;
											default:
												return Promise.reject("Incorrect public key algorithm: " + publicKeyInfo.algorithm.algorithmId);
										}
									}

									//region Create ECDSA Public Key elements
									var _publicKeyJSON2 = publicKeyInfo.toJSON();

									var _iteratorNormalCompletion3 = true;
									var _didIteratorError3 = false;
									var _iteratorError3 = undefined;

									try {
										for (var _iterator3 = Object.keys(_publicKeyJSON2)[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
											var _key2 = _step3.value;

											jwk[_key2] = _publicKeyJSON2[_key2];
										} //endregion
									} catch (err) {
										_didIteratorError3 = true;
										_iteratorError3 = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion3 && _iterator3.return) {
												_iterator3.return();
											}
										} finally {
											if (_didIteratorError3) {
												throw _iteratorError3;
											}
										}
									}
								}
								break;
							default:
								return Promise.reject("Incorrect algorithm name: " + algorithm.name.toUpperCase());
						}
					}
					break;
				case "pkcs8":
					{
						var privateKeyInfo = new _PrivateKeyInfo2.default();

						//region Parse "PrivateKeyInfo" object
						var _asn = asn1js.fromBER(keyData);
						if (_asn.offset === -1) return Promise.reject("Incorrect keyData");

						try {
							privateKeyInfo.fromSchema(_asn.result);
						} catch (ex) {
							return Promise.reject("Incorrect keyData");
						}
						//endregion

						switch (algorithm.name.toUpperCase()) {
							case "RSA-PSS":
								{
									//region Get information about used hash function
									switch (algorithm.hash.name.toUpperCase()) {
										case "SHA-1":
											jwk.alg = "PS1";
											break;
										case "SHA-256":
											jwk.alg = "PS256";
											break;
										case "SHA-384":
											jwk.alg = "PS384";
											break;
										case "SHA-512":
											jwk.alg = "PS512";
											break;
										default:
											return Promise.reject("Incorrect hash algorithm: " + algorithm.hash.name.toUpperCase());
									}
									//endregion
								}
							case "RSASSA-PKCS1-V1_5":
								{
									keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key

									jwk.kty = "RSA";
									jwk.ext = extractable;
									jwk.key_ops = keyUsages;

									//region Get information about used hash function
									if (privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.113549.1.1.1") return Promise.reject("Incorrect private key algorithm: " + privateKeyInfo.privateKeyAlgorithm.algorithmId);
									//endregion

									//region Get information about used hash function
									if ("alg" in jwk === false) {
										switch (algorithm.hash.name.toUpperCase()) {
											case "SHA-1":
												jwk.alg = "RS1";
												break;
											case "SHA-256":
												jwk.alg = "RS256";
												break;
											case "SHA-384":
												jwk.alg = "RS384";
												break;
											case "SHA-512":
												jwk.alg = "RS512";
												break;
											default:
												return Promise.reject("Incorrect hash algorithm: " + algorithm.hash.name.toUpperCase());
										}
									}
									//endregion

									//region Create RSA Private Key elements
									var privateKeyJSON = privateKeyInfo.toJSON();

									var _iteratorNormalCompletion4 = true;
									var _didIteratorError4 = false;
									var _iteratorError4 = undefined;

									try {
										for (var _iterator4 = Object.keys(privateKeyJSON)[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
											var _key3 = _step4.value;

											jwk[_key3] = privateKeyJSON[_key3];
										} //endregion
									} catch (err) {
										_didIteratorError4 = true;
										_iteratorError4 = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion4 && _iterator4.return) {
												_iterator4.return();
											}
										} finally {
											if (_didIteratorError4) {
												throw _iteratorError4;
											}
										}
									}
								}
								break;
							case "ECDSA":
								keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key
							case "ECDH":
								{
									//region Initial variables
									jwk = {
										kty: "EC",
										ext: extractable,
										key_ops: keyUsages
									};
									//endregion

									//region Get information about used hash function
									if (privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.10045.2.1") return Promise.reject("Incorrect algorithm: " + privateKeyInfo.privateKeyAlgorithm.algorithmId);
									//endregion

									//region Create ECDSA Private Key elements
									var _privateKeyJSON = privateKeyInfo.toJSON();

									var _iteratorNormalCompletion5 = true;
									var _didIteratorError5 = false;
									var _iteratorError5 = undefined;

									try {
										for (var _iterator5 = Object.keys(_privateKeyJSON)[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
											var _key4 = _step5.value;

											jwk[_key4] = _privateKeyJSON[_key4];
										} //endregion
									} catch (err) {
										_didIteratorError5 = true;
										_iteratorError5 = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion5 && _iterator5.return) {
												_iterator5.return();
											}
										} finally {
											if (_didIteratorError5) {
												throw _iteratorError5;
											}
										}
									}
								}
								break;
							case "RSA-OAEP":
								{
									jwk.kty = "RSA";
									jwk.ext = extractable;
									jwk.key_ops = keyUsages;

									//region Get information about used hash function
									if (this.name.toLowerCase() === "safari") jwk.alg = "RSA-OAEP";else {
										switch (algorithm.hash.name.toUpperCase()) {
											case "SHA-1":
												jwk.alg = "RSA-OAEP-1";
												break;
											case "SHA-256":
												jwk.alg = "RSA-OAEP-256";
												break;
											case "SHA-384":
												jwk.alg = "RSA-OAEP-384";
												break;
											case "SHA-512":
												jwk.alg = "RSA-OAEP-512";
												break;
											default:
												return Promise.reject("Incorrect hash algorithm: " + algorithm.hash.name.toUpperCase());
										}
									}
									//endregion

									//region Create RSA Private Key elements
									var _privateKeyJSON2 = privateKeyInfo.toJSON();

									var _iteratorNormalCompletion6 = true;
									var _didIteratorError6 = false;
									var _iteratorError6 = undefined;

									try {
										for (var _iterator6 = Object.keys(_privateKeyJSON2)[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
											var _key5 = _step6.value;

											jwk[_key5] = _privateKeyJSON2[_key5];
										} //endregion
									} catch (err) {
										_didIteratorError6 = true;
										_iteratorError6 = err;
									} finally {
										try {
											if (!_iteratorNormalCompletion6 && _iterator6.return) {
												_iterator6.return();
											}
										} finally {
											if (_didIteratorError6) {
												throw _iteratorError6;
											}
										}
									}
								}
								break;
							default:
								return Promise.reject("Incorrect algorithm name: " + algorithm.name.toUpperCase());
						}
					}
					break;
				case "jwk":
					jwk = keyData;
					break;
				default:
					return Promise.reject("Incorrect format: " + format);
			}

			//region Special case for Safari browser (since its acting not as WebCrypto standard describes)
			if (this.name.toLowerCase() === "safari") {
				if (jwk instanceof ArrayBuffer === false) jwk = (0, _pvutils.stringToArrayBuffer)(JSON.stringify(jwk));
			}
			//endregion

			return this.crypto.importKey("jwk", jwk, algorithm, extractable, keyUsages);
		}
		//**********************************************************************************
		/**
   * Export WebCrypto keys to different formats
   * @param {string} format
   * @param {Object} key
   * @returns {Promise}
   */

	}, {
		key: "exportKey",
		value: function exportKey(format, key) {
			var sequence = this.crypto.exportKey("jwk", key);

			//region Currently Safari returns ArrayBuffer as JWK thus we need an additional transformation
			if (this.name.toLowerCase() === "safari") sequence = sequence.then(function (result) {
				return JSON.parse((0, _pvutils.arrayBufferToString)(result));
			});
			//endregion

			switch (format.toLowerCase()) {
				case "raw":
					return this.crypto.exportKey("raw", key);
				case "spki":
					sequence = sequence.then(function (result) {
						var publicKeyInfo = new _PublicKeyInfo2.default();

						try {
							publicKeyInfo.fromJSON(result);
						} catch (ex) {
							return Promise.reject("Incorrect key data");
						}

						return publicKeyInfo.toSchema().toBER(false);
					});
					break;
				case "pkcs8":
					sequence = sequence.then(function (result) {
						var privateKeyInfo = new _PrivateKeyInfo2.default();

						try {
							privateKeyInfo.fromJSON(result);
						} catch (ex) {
							return Promise.reject("Incorrect key data");
						}

						return privateKeyInfo.toSchema().toBER(false);
					});
					break;
				case "jwk":
					break;
				default:
					return Promise.reject("Incorrect format: " + format);
			}

			return sequence;
		}
		//**********************************************************************************
		/**
   * Convert WebCrypto keys between different export formats
   * @param {string} inputFormat
   * @param {string} outputFormat
   * @param {ArrayBuffer|Object} keyData
   * @param {Object} algorithm
   * @param {boolean} extractable
   * @param {Array} keyUsages
   * @returns {Promise}
   */

	}, {
		key: "convert",
		value: function convert(inputFormat, outputFormat, keyData, algorithm, extractable, keyUsages) {
			var _this = this;

			switch (inputFormat.toLowerCase()) {
				case "raw":
					switch (outputFormat.toLowerCase()) {
						case "raw":
							return Promise.resolve(keyData);
						case "spki":
							return Promise.resolve().then(function () {
								return _this.importKey("raw", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("spki", result);
							});
						case "pkcs8":
							return Promise.resolve().then(function () {
								return _this.importKey("raw", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("pkcs8", result);
							});
						case "jwk":
							return Promise.resolve().then(function () {
								return _this.importKey("raw", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("jwk", result);
							});
						default:
							return Promise.reject("Incorrect outputFormat: " + outputFormat);
					}
				case "spki":
					switch (outputFormat.toLowerCase()) {
						case "raw":
							return Promise.resolve().then(function () {
								return _this.importKey("spki", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("raw", result);
							});
						case "spki":
							return Promise.resolve(keyData);
						case "pkcs8":
							return Promise.reject("Impossible to convert between SPKI/PKCS8");
						case "jwk":
							return Promise.resolve().then(function () {
								return _this.importKey("spki", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("jwk", result);
							});
						default:
							return Promise.reject("Incorrect outputFormat: " + outputFormat);
					}
				case "pkcs8":
					switch (outputFormat.toLowerCase()) {
						case "raw":
							return Promise.resolve().then(function () {
								return _this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("raw", result);
							});
						case "spki":
							return Promise.reject("Impossible to convert between SPKI/PKCS8");
						case "pkcs8":
							return Promise.resolve(keyData);
						case "jwk":
							return Promise.resolve().then(function () {
								return _this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("jwk", result);
							});
						default:
							return Promise.reject("Incorrect outputFormat: " + outputFormat);
					}
				case "jwk":
					switch (outputFormat.toLowerCase()) {
						case "raw":
							return Promise.resolve().then(function () {
								return _this.importKey("jwk", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("raw", result);
							});
						case "spki":
							return Promise.resolve().then(function () {
								return _this.importKey("jwk", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("spki", result);
							});
						case "pkcs8":
							return Promise.resolve().then(function () {
								return _this.importKey("jwk", keyData, algorithm, extractable, keyUsages);
							}).then(function (result) {
								return _this.exportKey("pkcs8", result);
							});
						case "jwk":
							return Promise.resolve(keyData);
						default:
							return Promise.reject("Incorrect outputFormat: " + outputFormat);
					}
				default:
					return Promise.reject("Incorrect inputFormat: " + inputFormat);
			}
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "encrypt"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "encrypt",
		value: function encrypt() {
			var _crypto;

			return (_crypto = this.crypto).encrypt.apply(_crypto, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "decrypt"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "decrypt",
		value: function decrypt() {
			var _crypto2;

			return (_crypto2 = this.crypto).decrypt.apply(_crypto2, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "sign"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "sign",
		value: function sign() {
			var _crypto3;

			return (_crypto3 = this.crypto).sign.apply(_crypto3, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "verify"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _crypto4;

			return (_crypto4 = this.crypto).verify.apply(_crypto4, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "digest"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "digest",
		value: function digest() {
			var _crypto5;

			return (_crypto5 = this.crypto).digest.apply(_crypto5, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "generateKey"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "generateKey",
		value: function generateKey() {
			var _crypto6;

			return (_crypto6 = this.crypto).generateKey.apply(_crypto6, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "deriveKey"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "deriveKey",
		value: function deriveKey() {
			var _crypto7;

			return (_crypto7 = this.crypto).deriveKey.apply(_crypto7, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "deriveBits"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "deriveBits",
		value: function deriveBits() {
			var _crypto8;

			return (_crypto8 = this.crypto).deriveBits.apply(_crypto8, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "wrapKey"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "wrapKey",
		value: function wrapKey() {
			var _crypto9;

			return (_crypto9 = this.crypto).wrapKey.apply(_crypto9, arguments);
		}
		//**********************************************************************************
		/**
   * Wrapper for standard function "unwrapKey"
   * @param args
   * @returns {Promise}
   */

	}, {
		key: "unwrapKey",
		value: function unwrapKey() {
			var _crypto10;

			return (_crypto10 = this.crypto).unwrapKey.apply(_crypto10, arguments);
		}
		//**********************************************************************************

	}]);

	return CryptoEngine;
}();
//**************************************************************************************


exports.default = CryptoEngine;
//# sourceMappingURL=CryptoEngine.js.map