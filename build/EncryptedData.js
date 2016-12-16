"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _EncryptedContentInfo = require("./EncryptedContentInfo");

var _EncryptedContentInfo2 = _interopRequireDefault(_EncryptedContentInfo);

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _PBKDF2Params = require("./PBKDF2Params");

var _PBKDF2Params2 = _interopRequireDefault(_PBKDF2Params);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _PBES2Params = require("./PBES2Params");

var _PBES2Params2 = _interopRequireDefault(_PBES2Params);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var EncryptedData = function () {
	//**********************************************************************************
	/**
  * Constructor for EncryptedData class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function EncryptedData() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, EncryptedData);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", EncryptedData.defaultValues("version"));
		/**
   * @type {EncryptedContentInfo}
   * @description encryptedContentInfo
   */
		this.encryptedContentInfo = (0, _pvutils.getParametersValue)(parameters, "encryptedContentInfo", EncryptedData.defaultValues("encryptedContentInfo"));

		if ("unprotectedAttrs" in parameters)
			/**
    * @type {Array.<Attribute>}
    * @description unprotectedAttrs
    */
			this.unprotectedAttrs = (0, _pvutils.getParametersValue)(parameters, "unprotectedAttrs", EncryptedData.defaultValues("unprotectedAttrs"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(EncryptedData, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, EncryptedData.schema({
				names: {
					version: "version",
					encryptedContentInfo: {
						names: {
							blockName: "encryptedContentInfo"
						}
					},
					unprotectedAttrs: "unprotectedAttrs"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_ENCRYPTED_DATA");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;
			this.encryptedContentInfo = new _EncryptedContentInfo2.default({ schema: asn1.result.encryptedContentInfo });

			if ("unprotectedAttrs" in asn1.result) this.unprotectedAttrs = Array.from(asn1.result.unprotectedAttrs, function (element) {
				return new _Attribute2.default({ schema: element });
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(new asn1js.Integer({ value: this.version }));
			outputArray.push(this.encryptedContentInfo.toSchema());

			if ("unprotectedAttrs" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: Array.from(this.unprotectedAttrs, function (element) {
						return element.toSchema();
					})
				}));
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {
				version: this.version,
				encryptedContentInfo: this.encryptedContentInfo.toJSON()
			};

			if ("unprotectedAttrs" in this) _object.unprotectedAttrs = Array.from(this.unprotectedAttrs, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************
		/**
   * Create a new CMS Encrypted Data content
   * @param {Object} parameters Parameters neccessary for encryption
   * @returns {Promise}
   */

	}, {
		key: "encrypt",
		value: function encrypt(parameters) {
			var _this = this;

			//region Check for input parameters
			if (parameters instanceof Object === false) return Promise.reject("Parameters must have type \"Object\"");

			if ("password" in parameters === false) return Promise.reject("Absent mandatory parameter \"password\"");

			if ("contentEncryptionAlgorithm" in parameters === false) return Promise.reject("Absent mandatory parameter \"contentEncryptionAlgorithm\"");

			if ("hmacHashAlgorithm" in parameters === false) return Promise.reject("Absent mandatory parameter \"hmacHashAlgorithm\"");

			if ("iterationCount" in parameters === false) return Promise.reject("Absent mandatory parameter \"iterationCount\"");

			if ("contentToEncrypt" in parameters === false) return Promise.reject("Absent mandatory parameter \"contentToEncrypt\"");

			var contentEncryptionOID = (0, _common.getOIDByAlgorithm)(parameters.contentEncryptionAlgorithm);
			if (contentEncryptionOID === "") return Promise.reject("Wrong \"contentEncryptionAlgorithm\" value");

			var pbkdf2OID = (0, _common.getOIDByAlgorithm)({
				name: "PBKDF2"
			});
			if (pbkdf2OID === "") return Promise.reject("Can not find OID for PBKDF2");

			var hmacOID = (0, _common.getOIDByAlgorithm)({
				name: "HMAC",
				hash: {
					name: parameters.hmacHashAlgorithm
				}
			});
			if (hmacOID === "") return Promise.reject("Incorrect value for \"hmacHashAlgorithm\": " + parameters.hmacHashAlgorithm);
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();

			var ivBuffer = new ArrayBuffer(16); // For AES we need IV 16 bytes long
			var ivView = new Uint8Array(ivBuffer);
			(0, _common.getRandomValues)(ivView);

			var saltBuffer = new ArrayBuffer(64);
			var saltView = new Uint8Array(saltBuffer);
			(0, _common.getRandomValues)(saltView);

			var contentView = new Uint8Array(parameters.contentToEncrypt);

			var pbkdf2Params = new _PBKDF2Params2.default({
				salt: new asn1js.OctetString({ valueHex: saltBuffer }),
				iterationCount: parameters.iterationCount,
				prf: new _AlgorithmIdentifier2.default({
					algorithmId: hmacOID,
					algorithmParams: new asn1js.Null()
				})
			});
			//endregion

			//region Derive PBKDF2 key from "password" buffer
			sequence = sequence.then(function () {
				var passwordView = new Uint8Array(parameters.password);

				return crypto.importKey("raw", passwordView, "PBKDF2", true, ["deriveKey"]);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Derive key for "contentEncryptionAlgorithm"
			sequence = sequence.then(function (result) {
				return crypto.deriveKey({
					name: "PBKDF2",
					hash: {
						name: parameters.hmacHashAlgorithm
					},
					salt: saltView,
					iterations: parameters.iterationCount
				}, result, parameters.contentEncryptionAlgorithm, true, ["encrypt"]);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Encrypt content
			sequence = sequence.then(function (result) {
				return crypto.encrypt({
					name: parameters.contentEncryptionAlgorithm.name,
					iv: ivView
				}, result, contentView);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Store all parameters in CMS_ENCRYPTED_DATA
			sequence = sequence.then(function (result) {
				var pbes2Parameters = new _PBES2Params2.default({
					keyDerivationFunc: new _AlgorithmIdentifier2.default({
						algorithmId: pbkdf2OID,
						algorithmParams: pbkdf2Params.toSchema()
					}),
					encryptionScheme: new _AlgorithmIdentifier2.default({
						algorithmId: contentEncryptionOID,
						algorithmParams: new asn1js.OctetString({ valueHex: ivBuffer })
					})
				});

				_this.encryptedContentInfo = new _EncryptedContentInfo2.default({
					contentType: "1.2.840.113549.1.7.1", // "data"
					contentEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
						algorithmId: "1.2.840.113549.1.5.13", // pkcs5PBES2
						algorithmParams: pbes2Parameters.toSchema()
					}),
					encryptedContent: new asn1js.OctetString({ valueHex: result })
				});
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************
		/**
   * Create a new CMS Encrypted Data content
   * @param {Object} parameters Parameters neccessary for encryption
   */

	}, {
		key: "decrypt",
		value: function decrypt(parameters) {
			var _this2 = this;

			//region Check for input parameters
			if (parameters instanceof Object === false) return Promise.reject("Parameters must have type \"Object\"");

			if ("password" in parameters === false) return Promise.reject("Absent mandatory parameter \"password\"");

			if (this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId !== "1.2.840.113549.1.5.13") // pkcs5PBES2
				return Promise.reject("Unknown \"contentEncryptionAlgorithm\": " + this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();

			var pbes2Parameters = void 0;

			try {
				pbes2Parameters = new _PBES2Params2.default({ schema: this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmParams });
			} catch (ex) {
				return Promise.reject("Incorrectly encoded \"pbes2Parameters\"");
			}

			var pbkdf2Params = void 0;

			try {
				pbkdf2Params = new _PBKDF2Params2.default({ schema: pbes2Parameters.keyDerivationFunc.algorithmParams });
			} catch (ex) {
				return Promise.reject("Incorrectly encoded \"pbkdf2Params\"");
			}

			var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(pbes2Parameters.encryptionScheme.algorithmId);
			if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect OID for \"contentEncryptionAlgorithm\": " + pbes2Parameters.encryptionScheme.algorithmId);

			var ivBuffer = pbes2Parameters.encryptionScheme.algorithmParams.valueBlock.valueHex;
			var ivView = new Uint8Array(ivBuffer);

			var saltBuffer = pbkdf2Params.salt.valueBlock.valueHex;
			var saltView = new Uint8Array(saltBuffer);

			var iterationCount = pbkdf2Params.iterationCount;

			var hmacHashAlgorithm = "SHA-1";

			if ("prf" in pbkdf2Params) {
				var algorithm = (0, _common.getAlgorithmByOID)(pbkdf2Params.prf.algorithmId);
				if ("name" in algorithm === false) return Promise.reject("Incorrect OID for HMAC hash algorithm");

				hmacHashAlgorithm = algorithm.hash.name;
			}
			//endregion

			//region Derive PBKDF2 key from "password" buffer
			sequence = sequence.then(function () {
				return crypto.importKey("raw", parameters.password, "PBKDF2", true, ["deriveKey"]);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Derive key for "contentEncryptionAlgorithm"
			sequence = sequence.then(function (result) {
				return crypto.deriveKey({
					name: "PBKDF2",
					hash: {
						name: hmacHashAlgorithm
					},
					salt: saltView,
					iterations: iterationCount
				}, result, contentEncryptionAlgorithm, true, ["decrypt"]);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Decrypt internal content using derived key
			sequence = sequence.then(function (result) {
				//region Create correct data block for decryption
				var dataBuffer = new ArrayBuffer(0);

				if (_this2.encryptedContentInfo.encryptedContent.idBlock.isConstructed === false) dataBuffer = _this2.encryptedContentInfo.encryptedContent.valueBlock.valueHex;else {
					var _iteratorNormalCompletion = true;
					var _didIteratorError = false;
					var _iteratorError = undefined;

					try {
						for (var _iterator = _this2.encryptedContentInfo.encryptedContent.valueBlock.value[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
							var content = _step.value;

							dataBuffer = (0, _pvutils.utilConcatBuf)(dataBuffer, content.valueBlock.valueHex);
						}
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
				//endregion

				return crypto.decrypt({
					name: contentEncryptionAlgorithm.name,
					iv: ivView
				}, result, dataBuffer);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 0;
				case "encryptedContentInfo":
					return new _EncryptedContentInfo2.default();
				case "unprotectedAttrs":
					return [];
				default:
					throw new Error("Invalid member name for EncryptedData class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "version":
					return memberValue === 0;
				case "encryptedContentInfo":
					return _EncryptedContentInfo2.default.compareWithDefault("contentType", memberValue.contentType) && _EncryptedContentInfo2.default.compareWithDefault("contentEncryptionAlgorithm", memberValue.contentEncryptionAlgorithm) && _EncryptedContentInfo2.default.compareWithDefault("encryptedContent", memberValue.encryptedContent);
				case "unprotectedAttrs":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for EncryptedData class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			//    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }

			//EncryptedData ::= SEQUENCE {
			//    version CMSVersion,
			//    encryptedContentInfo EncryptedContentInfo,
			//    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [encryptedContentInfo]
    * @property {string} [unprotectedAttrs]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), _EncryptedContentInfo2.default.schema(names.encryptedContentInfo || {}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Repeated({
						name: names.unprotectedAttrs || "",
						value: _Attribute2.default.schema()
					})]
				})]
			});
		}
	}]);

	return EncryptedData;
}();
//**************************************************************************************


exports.default = EncryptedData;
//# sourceMappingURL=EncryptedData.js.map