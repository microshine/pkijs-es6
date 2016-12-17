"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _OriginatorInfo = require("./OriginatorInfo");

var _OriginatorInfo2 = _interopRequireDefault(_OriginatorInfo);

var _RecipientInfo = require("./RecipientInfo");

var _RecipientInfo2 = _interopRequireDefault(_RecipientInfo);

var _EncryptedContentInfo = require("./EncryptedContentInfo");

var _EncryptedContentInfo2 = _interopRequireDefault(_EncryptedContentInfo);

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _RSAESOAEPParams = require("./RSAESOAEPParams");

var _RSAESOAEPParams2 = _interopRequireDefault(_RSAESOAEPParams);

var _KeyTransRecipientInfo = require("./KeyTransRecipientInfo");

var _KeyTransRecipientInfo2 = _interopRequireDefault(_KeyTransRecipientInfo);

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

var _RecipientEncryptedKey = require("./RecipientEncryptedKey");

var _RecipientEncryptedKey2 = _interopRequireDefault(_RecipientEncryptedKey);

var _KeyAgreeRecipientIdentifier = require("./KeyAgreeRecipientIdentifier");

var _KeyAgreeRecipientIdentifier2 = _interopRequireDefault(_KeyAgreeRecipientIdentifier);

var _KeyAgreeRecipientInfo = require("./KeyAgreeRecipientInfo");

var _KeyAgreeRecipientInfo2 = _interopRequireDefault(_KeyAgreeRecipientInfo);

var _RecipientEncryptedKeys = require("./RecipientEncryptedKeys");

var _RecipientEncryptedKeys2 = _interopRequireDefault(_RecipientEncryptedKeys);

var _KEKRecipientInfo = require("./KEKRecipientInfo");

var _KEKRecipientInfo2 = _interopRequireDefault(_KEKRecipientInfo);

var _KEKIdentifier = require("./KEKIdentifier");

var _KEKIdentifier2 = _interopRequireDefault(_KEKIdentifier);

var _PBKDF2Params = require("./PBKDF2Params");

var _PBKDF2Params2 = _interopRequireDefault(_PBKDF2Params);

var _PasswordRecipientinfo = require("./PasswordRecipientinfo");

var _PasswordRecipientinfo2 = _interopRequireDefault(_PasswordRecipientinfo);

var _ECCCMSSharedInfo = require("./ECCCMSSharedInfo");

var _ECCCMSSharedInfo2 = _interopRequireDefault(_ECCCMSSharedInfo);

var _OriginatorIdentifierOrKey = require("./OriginatorIdentifierOrKey");

var _OriginatorIdentifierOrKey2 = _interopRequireDefault(_OriginatorIdentifierOrKey);

var _OriginatorPublicKey = require("./OriginatorPublicKey");

var _OriginatorPublicKey2 = _interopRequireDefault(_OriginatorPublicKey);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var EnvelopedData = function () {
	//**********************************************************************************
	/**
  * Constructor for EnvelopedData class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function EnvelopedData() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, EnvelopedData);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", EnvelopedData.defaultValues("version"));

		if ("originatorInfo" in parameters)
			/**
    * @type {OriginatorInfo}
    * @description originatorInfo
    */
			this.originatorInfo = (0, _pvutils.getParametersValue)(parameters, "originatorInfo", EnvelopedData.defaultValues("originatorInfo"));

		/**
   * @type {Array.<RecipientInfo>}
   * @description recipientInfos
   */
		this.recipientInfos = (0, _pvutils.getParametersValue)(parameters, "recipientInfos", EnvelopedData.defaultValues("recipientInfos"));
		/**
   * @type {EncryptedContentInfo}
   * @description encryptedContentInfo
   */
		this.encryptedContentInfo = (0, _pvutils.getParametersValue)(parameters, "encryptedContentInfo", EnvelopedData.defaultValues("encryptedContentInfo"));

		if ("unprotectedAttrs" in parameters)
			/**
    * @type {Array.<Attribute>}
    * @description unprotectedAttrs
    */
			this.unprotectedAttrs = (0, _pvutils.getParametersValue)(parameters, "unprotectedAttrs", EnvelopedData.defaultValues("unprotectedAttrs"));
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


	_createClass(EnvelopedData, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, EnvelopedData.schema({
				names: {
					version: "version",
					originatorInfo: "originatorInfo",
					recipientInfos: "recipientInfos",
					encryptedContentInfo: {
						names: {
							blockName: "encryptedContentInfo"
						}
					},
					unprotectedAttrs: "unprotectedAttrs"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_ENVELOPED_DATA");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;

			if ("originatorInfo" in asn1.result) {
				asn1.result.originatorInfo.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.originatorInfo.idBlock.tagNumber = 16; // SEQUENCE

				this.originatorInfo = new _OriginatorInfo2.default({ schema: asn1.result.originatorInfo });
			}

			this.recipientInfos = Array.from(asn1.result.recipientInfos, function (element) {
				return new _RecipientInfo2.default({ schema: element });
			});
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

			if ("originatorInfo" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: this.originatorInfo.toSchema().valueBlock.value
				}));
			}

			outputArray.push(new asn1js.Set({
				value: Array.from(this.recipientInfos, function (element) {
					return element.toSchema();
				})
			}));

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
				version: this.version
			};

			if ("originatorInfo" in this) _object.originatorInfo = this.originatorInfo.toJSON();

			_object.recipientInfos = Array.from(this.recipientInfos, function (element) {
				return element.toJSON();
			});
			_object.encryptedContentInfo = this.encryptedContentInfo.toJSON();

			if ("unprotectedAttrs" in this) _object.unprotectedAttrs = Array.from(this.unprotectedAttrs, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************
		/**
   * Helpers function for filling "RecipientInfo" based on recipient's certificate.
   * Problem with WebCrypto is that for RSA certificates we have only one option - "key transport" and
   * for ECC certificates we also have one option - "key agreement". As soon as Google will implement
   * DH algorithm it would be possible to use "key agreement" also for RSA certificates.
   * @param {Certificate} [certificate] Recipient's certificate
   * @param {Object} [parameters] Additional parameters neccessary for "fine tunning" of encryption process
   * @param {number} [variant] Variant = 1 is for "key transport", variant = 2 is for "key agreement". In fact the "variant" is unneccessary now because Google has no DH algorithm implementation. Thus key encryption scheme would be choosen by certificate type only: "key transport" for RSA and "key agreement" for ECC certificates.
   */

	}, {
		key: "addRecipientByCertificate",
		value: function addRecipientByCertificate(certificate, parameters, variant) {
			//region Initial variables
			var encryptionParameters = parameters || {};
			//endregion

			//region Check type of certificate
			if (certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== -1) variant = 1; // For the moment it is the only variant for RSA-based certificates
			else {
					if (certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.10045") !== -1) variant = 2; // For the moment it is the only variant for ECC-based certificates
					else throw new Error("Unknown type of certificate's public key: " + certificate.subjectPublicKeyInfo.algorithm.algorithmId);
				}
			//endregion

			//region Initialize encryption parameters
			if ("oaepHashAlgorithm" in encryptionParameters === false) encryptionParameters.oaepHashAlgorithm = "SHA-512";

			if ("kdfAlgorithm" in encryptionParameters === false) encryptionParameters.kdfAlgorithm = "SHA-512";

			if ("kekEncryptionLength" in encryptionParameters === false) encryptionParameters.kekEncryptionLength = 256;
			//endregion

			//region Add new "recipient" depends on "variant" and certificate type
			switch (variant) {
				case 1:
					// Key transport scheme
					{
						//region keyEncryptionAlgorithm
						var oaepOID = (0, _common.getOIDByAlgorithm)({
							name: "RSA-OAEP"
						});
						if (oaepOID === "") throw new Error("Can not find OID for OAEP");
						//endregion

						//region RSAES-OAEP-params
						var hashOID = (0, _common.getOIDByAlgorithm)({
							name: encryptionParameters.oaepHashAlgorithm
						});
						if (hashOID === "") throw new Error("Unknown OAEP hash algorithm: " + encryptionParameters.oaepHashAlgorithm);

						var hashAlgorithm = new _AlgorithmIdentifier2.default({
							algorithmId: hashOID,
							algorithmParams: new asn1js.Null()
						});

						var rsaOAEPParams = new _RSAESOAEPParams2.default({
							hashAlgorithm: hashAlgorithm,
							maskGenAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: "1.2.840.113549.1.1.8", // id-mgf1
								algorithmParams: hashAlgorithm.toSchema()
							})
						});
						//endregion

						//region KeyTransRecipientInfo
						var keyInfo = new _KeyTransRecipientInfo2.default({
							version: 0,
							rid: new _IssuerAndSerialNumber2.default({
								issuer: certificate.issuer,
								serialNumber: certificate.serialNumber
							}),
							keyEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: oaepOID,
								algorithmParams: rsaOAEPParams.toSchema()
							}),
							recipientCertificate: certificate
							// "encryptedKey" will be calculated in "encrypt" function
						});
						//endregion

						//region Final values for "CMS_ENVELOPED_DATA"
						this.recipientInfos.push(new _RecipientInfo2.default({
							variant: 1,
							value: keyInfo
						}));
						//endregion
					}
					break;
				case 2:
					// Key agreement scheme
					{
						//region RecipientEncryptedKey
						var encryptedKey = new _RecipientEncryptedKey2.default({
							rid: new _KeyAgreeRecipientIdentifier2.default({
								variant: 1,
								value: new _IssuerAndSerialNumber2.default({
									issuer: certificate.issuer,
									serialNumber: certificate.serialNumber
								})
							})
							// "encryptedKey" will be calculated in "encrypt" function
						});
						//endregion

						//region keyEncryptionAlgorithm
						var aesKWoid = (0, _common.getOIDByAlgorithm)({
							name: "AES-KW",
							length: encryptionParameters.kekEncryptionLength
						});
						if (aesKWoid === "") throw new Error("Unknown length for key encryption algorithm: " + encryptionParameters.kekEncryptionLength);

						var aesKW = new _AlgorithmIdentifier2.default({
							algorithmId: aesKWoid,
							algorithmParams: new asn1js.Null()
						});
						//endregion

						//region KeyAgreeRecipientInfo
						var ecdhOID = (0, _common.getOIDByAlgorithm)({
							name: "ECDH",
							kdf: encryptionParameters.kdfAlgorithm
						});
						if (ecdhOID === "") throw new Error("Unknown KDF algorithm: " + encryptionParameters.kdfAlgorithm);

						// In fact there is no need in so long UKM, but RFC2631
						// has requirement that "UserKeyMaterial" must be 512 bits long
						var ukmBuffer = new ArrayBuffer(64);
						var ukmView = new Uint8Array(ukmBuffer);
						(0, _common.getRandomValues)(ukmView); // Generate random values in 64 bytes long buffer

						var _keyInfo = new _KeyAgreeRecipientInfo2.default({
							version: 3,
							// "originator" will be calculated in "encrypt" function because ephemeral key would be generated there
							ukm: new asn1js.OctetString({ valueHex: ukmBuffer }),
							keyEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: ecdhOID,
								algorithmParams: aesKW.toSchema()
							}),
							recipientEncryptedKeys: new _RecipientEncryptedKeys2.default({
								encryptedKeys: [encryptedKey]
							}),
							recipientCertificate: certificate
						});
						//endregion

						//region Final values for "CMS_ENVELOPED_DATA"
						this.recipientInfos.push(new _RecipientInfo2.default({
							variant: 2,
							value: _keyInfo
						}));
						//endregion
					}
					break;
				default:
					throw new Error("Unknown \"variant\" value: " + variant);
			}
			//endregion

			return true;
		}
		//**********************************************************************************
		/**
   * Add recipient based on pre-defined data like password or KEK
   * @param {ArrayBuffer} preDefinedData ArrayBuffer with pre-defined data
   * @param {Object} parameters Additional parameters neccessary for "fine tunning" of encryption process
   * @param {number} variant Variant = 1 for pre-defined "key encryption key" (KEK). Variant = 2 for password-based encryption.
   */

	}, {
		key: "addRecipientByPreDefinedData",
		value: function addRecipientByPreDefinedData(preDefinedData, parameters, variant) {
			//region Initial variables
			var encryptionParameters = parameters || {};
			//endregion

			//region Check initial parameters
			if (preDefinedData instanceof ArrayBuffer === false) throw new Error("Please pass \"preDefinedData\" in ArrayBuffer type");

			if (preDefinedData.byteLength === 0) throw new Error("Pre-defined data could have zero length");
			//endregion

			//region Initialize encryption parameters
			if ("keyIdentifier" in encryptionParameters === false) {
				var keyIdentifierBuffer = new ArrayBuffer(16);
				var keyIdentifierView = new Uint8Array(keyIdentifierBuffer);
				(0, _common.getRandomValues)(keyIdentifierView);

				encryptionParameters.keyIdentifier = keyIdentifierBuffer;
			}

			if ("hmacHashAlgorithm" in encryptionParameters === false) encryptionParameters.hmacHashAlgorithm = "SHA-512";

			if ("iterationCount" in encryptionParameters === false) encryptionParameters.iterationCount = 2048;

			if ("keyEncryptionAlgorithm" in encryptionParameters === false) {
				encryptionParameters.keyEncryptionAlgorithm = {
					name: "AES-KW",
					length: 256
				};
			}

			if ("keyEncryptionAlgorithmParams" in encryptionParameters === false) encryptionParameters.keyEncryptionAlgorithmParams = new asn1js.Null();
			//endregion

			//region Add new recipient based on passed variant
			switch (variant) {
				case 1:
					// KEKRecipientInfo
					{
						//region keyEncryptionAlgorithm
						var kekOID = (0, _common.getOIDByAlgorithm)(encryptionParameters.keyEncryptionAlgorithm);
						if (kekOID === "") throw new Error("Incorrect value for \"keyEncryptionAlgorithm\"");
						//endregion

						//region KEKRecipientInfo
						var keyInfo = new _KEKRecipientInfo2.default({
							version: 4,
							kekid: new _KEKIdentifier2.default({
								keyIdentifier: new asn1js.OctetString({ valueHex: encryptionParameters.keyIdentifier })
							}),
							keyEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: kekOID,
								/*
         For AES-KW params are NULL, but for other algorithm could another situation.
         */
								algorithmParams: encryptionParameters.keyEncryptionAlgorithmParams
							}),
							preDefinedKEK: preDefinedData
							// "encryptedKey" would be set in "ecrypt" function
						});
						//endregion

						//region Final values for "CMS_ENVELOPED_DATA"
						this.recipientInfos.push(new _RecipientInfo2.default({
							variant: 3,
							value: keyInfo
						}));
						//endregion
					}
					break;
				case 2:
					// PasswordRecipientinfo
					{
						//region keyDerivationAlgorithm
						var pbkdf2OID = (0, _common.getOIDByAlgorithm)({
							name: "PBKDF2"
						});
						if (pbkdf2OID === "") throw new Error("Can not find OID for PBKDF2");
						//endregion

						//region Salt
						var saltBuffer = new ArrayBuffer(64);
						var saltView = new Uint8Array(saltBuffer);
						(0, _common.getRandomValues)(saltView);
						//endregion

						//region HMAC-based algorithm
						var hmacOID = (0, _common.getOIDByAlgorithm)({
							name: "HMAC",
							hash: {
								name: encryptionParameters.hmacHashAlgorithm
							}
						});
						if (hmacOID === "") throw new Error("Incorrect value for \"hmacHashAlgorithm\": " + encryptionParameters.hmacHashAlgorithm);
						//endregion

						//region PBKDF2-params
						var pbkdf2Params = new _PBKDF2Params2.default({
							salt: new asn1js.OctetString({ valueHex: saltBuffer }),
							iterationCount: encryptionParameters.iterationCount,
							prf: new _AlgorithmIdentifier2.default({
								algorithmId: hmacOID,
								algorithmParams: new asn1js.Null()
							})
						});
						//endregion

						//region keyEncryptionAlgorithm
						var _kekOID = (0, _common.getOIDByAlgorithm)(encryptionParameters.keyEncryptionAlgorithm);
						if (_kekOID === "") throw new Error("Incorrect value for \"keyEncryptionAlgorithm\"");
						//endregion

						//region PasswordRecipientinfo
						var _keyInfo2 = new _PasswordRecipientinfo2.default({
							version: 0,
							keyDerivationAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: pbkdf2OID,
								algorithmParams: pbkdf2Params.toSchema()
							}),
							keyEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
								algorithmId: _kekOID,
								/*
         For AES-KW params are NULL, but for other algorithm could be another situation.
         */
								algorithmParams: encryptionParameters.keyEncryptionAlgorithmParams
							}),
							password: preDefinedData
							// "encryptedKey" would be set in "ecrypt" function
						});
						//endregion

						//region Final values for "CMS_ENVELOPED_DATA"
						this.recipientInfos.push(new _RecipientInfo2.default({
							variant: 4,
							value: _keyInfo2
						}));
						//endregion
					}
					break;
				default:
					throw new Error("Unknown value for \"variant\": " + variant);
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Create a new CMS Enveloped Data content with encrypted data
   * @param {Object} contentEncryptionAlgorithm WebCrypto algorithm. For the moment here could be only "AES-CBC" or "AES-GCM" algorithms.
   * @param {ArrayBuffer} contentToEncrypt Content to encrypt
   * @returns {Promise}
   */

	}, {
		key: "encrypt",
		value: function encrypt(contentEncryptionAlgorithm, contentToEncrypt) {
			var _this2 = this;

			//region Initial variables
			var sequence = Promise.resolve();

			var ivBuffer = new ArrayBuffer(16); // For AES we need IV 16 bytes long
			var ivView = new Uint8Array(ivBuffer);
			(0, _common.getRandomValues)(ivView);

			var contentView = new Uint8Array(contentToEncrypt);

			var sessionKey = void 0;
			var encryptedContent = void 0;
			var exportedSessionKey = void 0;

			var recipientsPromises = [];

			var _this = this;
			//endregion

			//region Check for input parameters
			var contentEncryptionOID = (0, _common.getOIDByAlgorithm)(contentEncryptionAlgorithm);
			if (contentEncryptionOID === "") return Promise.reject("Wrong \"contentEncryptionAlgorithm\" value");
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Generate new content encryption key
			sequence = sequence.then(function () {
				return crypto.generateKey(contentEncryptionAlgorithm, true, ["encrypt"]);
			});
			//endregion
			//region Encrypt content
			sequence = sequence.then(function (result) {
				sessionKey = result;

				return crypto.encrypt({
					name: contentEncryptionAlgorithm.name,
					iv: ivView
				}, sessionKey, contentView);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion
			//region Export raw content of content encryption key
			sequence = sequence.then(function (result) {
				//region Create output OCTETSTRING with encrypted content
				encryptedContent = result;
				//endregion

				return crypto.exportKey("raw", sessionKey);
			}, function (error) {
				return Promise.reject(error);
			}).then(function (result) {
				exportedSessionKey = result;

				return true;
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion
			//region Append common information to CMS_ENVELOPED_DATA
			sequence = sequence.then(function () {
				_this2.version = 2;
				_this2.encryptedContentInfo = new _EncryptedContentInfo2.default({
					contentType: "1.2.840.113549.1.7.1", // "data"
					contentEncryptionAlgorithm: new _AlgorithmIdentifier2.default({
						algorithmId: contentEncryptionOID,
						algorithmParams: new asn1js.OctetString({ valueHex: ivBuffer })
					}),
					encryptedContent: new asn1js.OctetString({ valueHex: encryptedContent })
				});
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Special sub-functions to work with each recipient's type
			function SubKeyAgreeRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();

				var ecdhPublicKey = void 0;
				var ecdhPrivateKey = void 0;

				var recipientCurve = void 0;
				var recipientCurveLength = void 0;

				var exportedECDHPublicKey = void 0;
				//endregion

				//region Get "namedCurve" parameter from recipient's certificate
				currentSequence = currentSequence.then(function () {
					var curveObject = _this.recipientInfos[index].value.recipientCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;

					if (curveObject instanceof asn1js.ObjectIdentifier === false) return Promise.reject("Incorrect \"recipientCertificate\" for index " + index);

					var curveOID = curveObject.valueBlock.toString();

					switch (curveOID) {
						case "1.2.840.10045.3.1.7":
							recipientCurve = "P-256";
							recipientCurveLength = 256;
							break;
						case "1.3.132.0.34":
							recipientCurve = "P-384";
							recipientCurveLength = 384;
							break;
						case "1.3.132.0.35":
							recipientCurve = "P-521";
							recipientCurveLength = 528;
							break;
						default:
							return Promise.reject("Incorrect curve OID for index " + index);
					}

					return recipientCurve;
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Generate ephemeral ECDH key
				currentSequence = currentSequence.then(function (result) {
					return crypto.generateKey({
						name: "ECDH",
						namedCurve: result
					}, true, ["deriveBits"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Export public key of ephemeral ECDH key pair
				currentSequence = currentSequence.then(function (result) {
					ecdhPublicKey = result.publicKey;
					ecdhPrivateKey = result.privateKey;

					return crypto.exportKey("spki", ecdhPublicKey);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Import recipient's public key
				currentSequence = currentSequence.then(function (result) {
					exportedECDHPublicKey = result;

					return _this.recipientInfos[index].value.recipientCertificate.getPublicKey({
						algorithm: {
							algorithm: {
								name: "ECDH",
								namedCurve: recipientCurve
							},
							usages: []
						}
					});
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Create shared secret
				currentSequence = currentSequence.then(function (result) {
					return crypto.deriveBits({
						name: "ECDH",
						public: result
					}, ecdhPrivateKey, recipientCurveLength);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Apply KDF function to shared secret
				currentSequence = currentSequence.then(function (result) {
					//region Get length of used AES-KW algorithm
					var aesKWAlgorithm = new _AlgorithmIdentifier2.default({ schema: _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams });

					var KWalgorithm = (0, _common.getAlgorithmByOID)(aesKWAlgorithm.algorithmId);
					if ("name" in KWalgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + aesKWAlgorithm.algorithmId);
					//endregion

					//region Translate AES-KW length to ArrayBuffer
					var kwLength = KWalgorithm.length;

					var kwLengthBuffer = new ArrayBuffer(4);
					var kwLengthView = new Uint8Array(kwLengthBuffer);

					for (var j = 3; j >= 0; j--) {
						kwLengthView[j] = kwLength;
						kwLength >>= 8;
					}
					//endregion

					//region Create and encode "ECC-CMS-SharedInfo" structure
					var eccInfo = new _ECCCMSSharedInfo2.default({
						keyInfo: new _AlgorithmIdentifier2.default({
							algorithmId: aesKWAlgorithm.algorithmId,
							/*
        Initially RFC5753 says that AES algorithms have absent parameters.
        But since early implementations all put NULL here. Thus, in order to be
        "backward compatible", index also put NULL here.
        */
							algorithmParams: new asn1js.Null()
						}),
						entityUInfo: _this.recipientInfos[index].value.ukm,
						suppPubInfo: new asn1js.OctetString({ valueHex: kwLengthBuffer })
					});

					var encodedInfo = eccInfo.toSchema().toBER(false);
					//endregion

					//region Get SHA algorithm used together with ECDH
					var ecdhAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in ecdhAlgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					return (0, _common.kdf)(ecdhAlgorithm.kdf, result, KWalgorithm.length, encodedInfo);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Import AES-KW key from result of KDF function
				currentSequence = currentSequence.then(function (result) {
					return crypto.importKey("raw", result, { name: "AES-KW" }, true, ["wrapKey"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Finally wrap session key by using AES-KW algorithm
				currentSequence = currentSequence.then(function (result) {
					return crypto.wrapKey("raw", sessionKey, result, { name: "AES-KW" });
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Append all neccessary data to current CMS_RECIPIENT_INFO object
				currentSequence = currentSequence.then(function (result) {
					//region OriginatorIdentifierOrKey
					var asn1 = asn1js.fromBER(exportedECDHPublicKey);

					var originator = new _OriginatorIdentifierOrKey2.default();
					originator.variant = 3;
					originator.value = new _OriginatorPublicKey2.default({ schema: asn1.result });
					// There is option when we can stay with ECParameters, but here index prefer to avoid the params
					if ("algorithmParams" in originator.value.algorithm) delete originator.value.algorithm.algorithmParams;

					_this.recipientInfos[index].value.originator = originator;
					//endregion

					//region RecipientEncryptedKey
					/*
      We will not support using of same ephemeral key for many recipients
      */
					_this.recipientInfos[index].value.recipientEncryptedKeys.encryptedKeys[0].encryptedKey = new asn1js.OctetString({ valueHex: result });
					//endregion
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubKeyTransRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				//endregion

				//region Get recipient's public key
				currentSequence = currentSequence.then(function () {
					//region Get current used SHA algorithm
					var schema = _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams;
					var rsaOAEPParams = new _RSAESOAEPParams2.default({ schema: schema });

					var hashAlgorithm = (0, _common.getAlgorithmByOID)(rsaOAEPParams.hashAlgorithm.algorithmId);
					if ("name" in hashAlgorithm === false) return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithmId);
					//endregion

					return _this.recipientInfos[index].value.recipientCertificate.getPublicKey({
						algorithm: {
							algorithm: {
								name: "RSA-OAEP",
								hash: {
									name: hashAlgorithm.name
								}
							},
							usages: ["encrypt", "wrapKey"]
						}
					});
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Encrypt early exported session key on recipient's public key
				currentSequence = currentSequence.then(function (result) {
					return crypto.encrypt(result.algorithm, result, exportedSessionKey);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Append all neccessary data to current CMS_RECIPIENT_INFO object
				currentSequence = currentSequence.then(function (result) {
					//region RecipientEncryptedKey
					_this.recipientInfos[index].value.encryptedKey = new asn1js.OctetString({ valueHex: result });
					//endregion
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubKEKRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				var kekAlgorithm = void 0;
				//endregion

				//region Import KEK from pre-defined data
				currentSequence = currentSequence.then(function () {
					//region Get WebCrypto form of "keyEncryptionAlgorithm"
					kekAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.importKey("raw", new Uint8Array(_this.recipientInfos[index].value.preDefinedKEK), kekAlgorithm, true, ["wrapKey"]); // Too specific for AES-KW
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Wrap previously exported session key
				currentSequence = currentSequence.then(function (result) {
					return crypto.wrapKey("raw", sessionKey, result, kekAlgorithm);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Append all neccessary data to current CMS_RECIPIENT_INFO object
				currentSequence = currentSequence.then(function (result) {
					//region RecipientEncryptedKey
					_this.recipientInfos[index].value.encryptedKey = new asn1js.OctetString({ valueHex: result });
					//endregion
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubPasswordRecipientinfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				var pbkdf2Params = void 0;
				var kekAlgorithm = void 0;
				//endregion

				//region Check that we have encoded "keyDerivationAlgorithm" plus "PBKDF2_params" in there
				currentSequence = currentSequence.then(function () {
					if ("keyDerivationAlgorithm" in _this.recipientInfos[index].value === false) return Promise.reject("Please append encoded \"keyDerivationAlgorithm\"");

					if ("algorithmParams" in _this.recipientInfos[index].value.keyDerivationAlgorithm === false) return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");

					try {
						pbkdf2Params = new _PBKDF2Params2.default({ schema: _this.recipientInfos[index].value.keyDerivationAlgorithm.algorithmParams });
					} catch (ex) {
						return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");
					}

					return Promise.resolve();
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Derive PBKDF2 key from "password" buffer
				currentSequence = currentSequence.then(function () {
					var passwordView = new Uint8Array(_this.recipientInfos[index].value.password);

					return crypto.importKey("raw", passwordView, "PBKDF2", true, ["deriveKey"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Derive key for "keyEncryptionAlgorithm"
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of "keyEncryptionAlgorithm"
					kekAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					//region Get HMAC hash algorithm
					var hmacHashAlgorithm = "SHA-1";

					if ("prf" in pbkdf2Params) {
						var algorithm = (0, _common.getAlgorithmByOID)(pbkdf2Params.prf.algorithmId);
						if ("name" in algorithm === false) return Promise.reject("Incorrect OID for HMAC hash algorithm");

						hmacHashAlgorithm = algorithm.hash.name;
					}
					//endregion

					//region Get PBKDF2 "salt" value
					var saltView = new Uint8Array(pbkdf2Params.salt.valueBlock.valueHex);
					//endregion

					//region Get PBKDF2 iterations count
					var iterations = pbkdf2Params.iterationCount;
					//endregion

					return crypto.deriveKey({
						name: "PBKDF2",
						hash: {
							name: hmacHashAlgorithm
						},
						salt: saltView,
						iterations: iterations
					}, result, kekAlgorithm, true, ["wrapKey"]); // Usages are too specific for KEK algorithm
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Wrap previously exported session key (Also too specific for KEK algorithm)
				currentSequence = currentSequence.then(function (result) {
					return crypto.wrapKey("raw", sessionKey, result, kekAlgorithm);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Append all neccessary data to current CMS_RECIPIENT_INFO object
				currentSequence = currentSequence.then(function (result) {
					//region RecipientEncryptedKey
					_this.recipientInfos[index].value.encryptedKey = new asn1js.OctetString({ valueHex: result });
					//endregion
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}
			//endregion

			//region Create special routines for each "recipient"
			sequence = sequence.then(function () {
				for (var i = 0; i < _this2.recipientInfos.length; i++) {
					//region Initial variables
					var currentSequence = Promise.resolve();
					//endregion

					switch (_this2.recipientInfos[i].variant) {
						case 1:
							// KeyTransRecipientInfo
							currentSequence = SubKeyTransRecipientInfo(i);
							break;
						case 2:
							// KeyAgreeRecipientInfo
							currentSequence = SubKeyAgreeRecipientInfo(i);
							break;
						case 3:
							// KEKRecipientInfo
							currentSequence = SubKEKRecipientInfo(i);
							break;
						case 4:
							// PasswordRecipientinfo
							currentSequence = SubPasswordRecipientinfo(i);
							break;
						default:
							return Promise.reject("Uknown recipient type in array with index " + i);
					}

					recipientsPromises.push(currentSequence);
				}

				return Promise.all(recipientsPromises);
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************
		/**
   * Decrypt existing CMS Enveloped Data content
   * @param {number} recipientIndex Index of recipient
   * @param {Object} parameters Additional parameters
   * @returns {Promise}
   */

	}, {
		key: "decrypt",
		value: function decrypt(recipientIndex, parameters) {
			var _this3 = this;

			//region Initial variables
			var sequence = Promise.resolve();

			var decryptionParameters = parameters || {};

			var _this = this;
			//endregion

			//region Check for input parameters
			if (recipientIndex + 1 > this.recipientInfos.length) return Promise.reject("Maximum value for \"index\" is: " + (this.recipientInfos.length - 1));
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Special sub-functions to work with each recipient's type
			function SubKeyAgreeRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();

				var recipientCurve = void 0;
				var recipientCurveLength = void 0;

				var curveOID = void 0;

				var ecdhPrivateKey = void 0;
				//endregion

				//region Get "namedCurve" parameter from recipient's certificate
				currentSequence = currentSequence.then(function () {
					if ("recipientCertificate" in decryptionParameters === false) return Promise.reject("Parameter \"recipientCertificate\" is mandatory for \"KeyAgreeRecipientInfo\"");

					if ("recipientPrivateKey" in decryptionParameters === false) return Promise.reject("Parameter \"recipientPrivateKey\" is mandatory for \"KeyAgreeRecipientInfo\"");

					var curveObject = decryptionParameters.recipientCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;

					if (curveObject instanceof asn1js.ObjectIdentifier === false) return Promise.reject("Incorrect \"recipientCertificate\" for index " + index);

					curveOID = curveObject.valueBlock.toString();

					switch (curveOID) {
						case "1.2.840.10045.3.1.7":
							recipientCurve = "P-256";
							recipientCurveLength = 256;
							break;
						case "1.3.132.0.34":
							recipientCurve = "P-384";
							recipientCurveLength = 384;
							break;
						case "1.3.132.0.35":
							recipientCurve = "P-521";
							recipientCurveLength = 528;
							break;
						default:
							return Promise.reject("Incorrect curve OID for index " + index);
					}

					return crypto.importKey("pkcs8", decryptionParameters.recipientPrivateKey, {
						name: "ECDH",
						namedCurve: recipientCurve
					}, true, ["deriveBits"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Import sender's ephemeral public key
				currentSequence = currentSequence.then(function (result) {
					ecdhPrivateKey = result;

					//region Change "OriginatorPublicKey" if "curve" parameter absent
					if ("algorithmParams" in _this.recipientInfos[index].value.originator.value.algorithm === false) _this.recipientInfos[index].value.originator.value.algorithm.algorithmParams = new asn1js.ObjectIdentifier({ value: curveOID });
					//endregion

					//region Create ArrayBuffer with sender's public key
					var buffer = _this.recipientInfos[index].value.originator.value.toSchema().toBER(false);
					//endregion

					return crypto.importKey("spki", buffer, {
						name: "ECDH",
						namedCurve: recipientCurve
					}, true, []);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Create shared secret
				currentSequence = currentSequence.then(function (result) {
					return crypto.deriveBits({
						name: "ECDH",
						public: result
					}, ecdhPrivateKey, recipientCurveLength);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Apply KDF function to shared secret
				currentSequence = currentSequence.then(function (result) {
					//region Get length of used AES-KW algorithm
					var aesKWAlgorithm = new _AlgorithmIdentifier2.default({ schema: _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams });

					var KWalgorithm = (0, _common.getAlgorithmByOID)(aesKWAlgorithm.algorithmId);
					if ("name" in KWalgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + aesKWAlgorithm.algorithmId);
					//endregion

					//region Translate AES-KW length to ArrayBuffer
					var kwLength = KWalgorithm.length;

					var kwLengthBuffer = new ArrayBuffer(4);
					var kwLengthView = new Uint8Array(kwLengthBuffer);

					for (var j = 3; j >= 0; j--) {
						kwLengthView[j] = kwLength;
						kwLength >>= 8;
					}
					//endregion

					//region Create and encode "ECC-CMS-SharedInfo" structure
					var eccInfo = new _ECCCMSSharedInfo2.default({
						keyInfo: new _AlgorithmIdentifier2.default({
							algorithmId: aesKWAlgorithm.algorithmId,
							/*
        Initially RFC5753 says that AES algorithms have absent parameters.
        But since early implementations all put NULL here. Thus, in order to be
        "backward compatible", index also put NULL here.
        */
							algorithmParams: new asn1js.Null()
						}),
						entityUInfo: _this.recipientInfos[index].value.ukm,
						suppPubInfo: new asn1js.OctetString({ valueHex: kwLengthBuffer })
					});

					var encodedInfo = eccInfo.toSchema().toBER(false);
					//endregion

					//region Get SHA algorithm used together with ECDH
					var ecdhAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in ecdhAlgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					return (0, _common.kdf)(ecdhAlgorithm.kdf, result, KWalgorithm.length, encodedInfo);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Import AES-KW key from result of KDF function
				currentSequence = currentSequence.then(function (result) {
					return crypto.importKey("raw", result, { name: "AES-KW" }, true, ["unwrapKey"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Finally unwrap session key
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of content encryption algorithm
					var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.unwrapKey("raw", _this.recipientInfos[index].value.recipientEncryptedKeys.encryptedKeys[0].encryptedKey.valueBlock.valueHex, result, { name: "AES-KW" }, contentEncryptionAlgorithm, true, ["decrypt"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubKeyTransRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				//endregion

				//region Import recipient's private key
				currentSequence = currentSequence.then(function () {
					if ("recipientPrivateKey" in decryptionParameters === false) return Promise.reject("Parameter \"recipientPrivateKey\" is mandatory for \"KeyTransRecipientInfo\"");

					//region Get current used SHA algorithm
					var schema = _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams;
					var rsaOAEPParams = new _RSAESOAEPParams2.default({ schema: schema });

					var hashAlgorithm = (0, _common.getAlgorithmByOID)(rsaOAEPParams.hashAlgorithm.algorithmId);
					if ("name" in hashAlgorithm === false) return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithmId);
					//endregion

					return crypto.importKey("pkcs8", decryptionParameters.recipientPrivateKey, {
						name: "RSA-OAEP",
						hash: {
							name: hashAlgorithm.name
						}
					}, true, ["decrypt"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Decrypt encrypted session key
				currentSequence = currentSequence.then(function (result) {
					return crypto.decrypt(result.algorithm, result, _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Import decrypted session key
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of content encryption algorithm
					var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.importKey("raw", result, contentEncryptionAlgorithm, true, ["decrypt"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubKEKRecipientInfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				var kekAlgorithm = void 0;
				//endregion

				//region Import KEK from pre-defined data
				currentSequence = currentSequence.then(function () {
					if ("preDefinedData" in decryptionParameters === false) return Promise.reject("Parameter \"preDefinedData\" is mandatory for \"KEKRecipientInfo\"");

					//region Get WebCrypto form of "keyEncryptionAlgorithm"
					kekAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.importKey("raw", decryptionParameters.preDefinedData, kekAlgorithm, true, ["unwrapKey"]); // Too specific for AES-KW
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Unwrap previously exported session key
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of content encryption algorithm
					var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.unwrapKey("raw", _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex, result, kekAlgorithm, contentEncryptionAlgorithm, true, ["decrypt"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}

			function SubPasswordRecipientinfo(index) {
				//region Initial variables
				var currentSequence = Promise.resolve();
				var pbkdf2Params = void 0;
				var kekAlgorithm = void 0;
				//endregion

				//region Derive PBKDF2 key from "password" buffer
				currentSequence = currentSequence.then(function () {
					if ("preDefinedData" in decryptionParameters === false) return Promise.reject("Parameter \"preDefinedData\" is mandatory for \"KEKRecipientInfo\"");

					if ("keyDerivationAlgorithm" in _this.recipientInfos[index].value === false) return Promise.reject("Please append encoded \"keyDerivationAlgorithm\"");

					if ("algorithmParams" in _this.recipientInfos[index].value.keyDerivationAlgorithm === false) return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");

					try {
						pbkdf2Params = new _PBKDF2Params2.default({ schema: _this.recipientInfos[index].value.keyDerivationAlgorithm.algorithmParams });
					} catch (ex) {
						return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");
					}

					return crypto.importKey("raw", decryptionParameters.preDefinedData, "PBKDF2", true, ["deriveKey"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Derive key for "keyEncryptionAlgorithm"
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of "keyEncryptionAlgorithm"
					kekAlgorithm = (0, _common.getAlgorithmByOID)(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
					//endregion

					//region Get HMAC hash algorithm
					var hmacHashAlgorithm = "SHA-1";

					if ("prf" in pbkdf2Params) {
						var algorithm = (0, _common.getAlgorithmByOID)(pbkdf2Params.prf.algorithmId);
						if ("name" in algorithm === false) return Promise.reject("Incorrect OID for HMAC hash algorithm");

						hmacHashAlgorithm = algorithm.hash.name;
					}
					//endregion

					//region Get PBKDF2 "salt" value
					var saltView = new Uint8Array(pbkdf2Params.salt.valueBlock.valueHex);
					//endregion

					//region Get PBKDF2 iterations count
					var iterations = pbkdf2Params.iterationCount;
					//endregion

					return crypto.deriveKey({
						name: "PBKDF2",
						hash: {
							name: hmacHashAlgorithm
						},
						salt: saltView,
						iterations: iterations
					}, result, kekAlgorithm, true, ["unwrapKey"]); // Usages are too specific for KEK algorithm
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion
				//region Unwrap previously exported session key
				currentSequence = currentSequence.then(function (result) {
					//region Get WebCrypto form of content encryption algorithm
					var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
					//endregion

					return crypto.unwrapKey("raw", _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex, result, kekAlgorithm, contentEncryptionAlgorithm, true, ["decrypt"]);
				}, function (error) {
					return Promise.reject(error);
				});
				//endregion

				return currentSequence;
			}
			//endregion

			//region Perform steps, specific to each type of session key encryption
			sequence = sequence.then(function () {
				//region Initial variables
				var currentSequence = Promise.resolve();
				//endregion

				switch (_this3.recipientInfos[recipientIndex].variant) {
					case 1:
						// KeyTransRecipientInfo
						currentSequence = SubKeyTransRecipientInfo(recipientIndex);
						break;
					case 2:
						// KeyAgreeRecipientInfo
						currentSequence = SubKeyAgreeRecipientInfo(recipientIndex);
						break;
					case 3:
						// KEKRecipientInfo
						currentSequence = SubKEKRecipientInfo(recipientIndex);
						break;
					case 4:
						// PasswordRecipientinfo
						currentSequence = SubPasswordRecipientinfo(recipientIndex);
						break;
					default:
						return Promise.reject("Uknown recipient type in array with index " + recipientIndex);
				}

				return currentSequence;
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Finally decrypt data by session key
			sequence = sequence.then(function (result) {
				//region Get WebCrypto form of content encryption algorithm
				var contentEncryptionAlgorithm = (0, _common.getAlgorithmByOID)(_this3.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
				if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this3.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
				//endregion

				//region Get "intialization vector" for content encryption algorithm
				var ivBuffer = _this3.encryptedContentInfo.contentEncryptionAlgorithm.algorithmParams.valueBlock.valueHex;
				var ivView = new Uint8Array(ivBuffer);
				//endregion

				//region Create correct data block for decryption
				var dataBuffer = new ArrayBuffer(0);

				if (_this3.encryptedContentInfo.encryptedContent.idBlock.isConstructed === false) dataBuffer = _this3.encryptedContentInfo.encryptedContent.valueBlock.valueHex;else {
					var _iteratorNormalCompletion = true;
					var _didIteratorError = false;
					var _iteratorError = undefined;

					try {
						for (var _iterator = _this3.encryptedContentInfo.encryptedContent.valueBlock.value[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
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
				case "originatorInfo":
					return new _OriginatorInfo2.default();
				case "recipientInfos":
					return [];
				case "encryptedContentInfo":
					return new _EncryptedContentInfo2.default();
				case "unprotectedAttrs":
					return [];
				default:
					throw new Error("Invalid member name for EnvelopedData class: " + memberName);
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
					return memberValue === EnvelopedData.defaultValues(memberName);
				case "originatorInfo":
					return memberValue.certs.certificates.length === 0 && memberValue.crls.crls.length === 0;
				case "recipientInfos":
				case "unprotectedAttrs":
					return memberValue.length === 0;
				case "encryptedContentInfo":
					return _EncryptedContentInfo2.default.compareWithDefault("contentType", memberValue.contentType) && _EncryptedContentInfo2.default.compareWithDefault("contentEncryptionAlgorithm", memberValue.contentEncryptionAlgorithm) && _EncryptedContentInfo2.default.compareWithDefault("encryptedContent", memberValue.encryptedContent);
				default:
					throw new Error("Invalid member name for EnvelopedData class: " + memberName);
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

			//EnvelopedData ::= SEQUENCE {
			//    version CMSVersion,
			//    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
			//    recipientInfos RecipientInfos,
			//    encryptedContentInfo EncryptedContentInfo,
			//    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [originatorInfo]
    * @property {string} [recipientInfos]
    * @property {string} [encryptedContentInfo]
    * @property {string} [unprotectedAttrs]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), new asn1js.Constructed({
					name: names.originatorInfo || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: _OriginatorInfo2.default.schema().valueBlock.value
				}), new asn1js.Set({
					value: [new asn1js.Repeated({
						name: names.recipientInfos || "",
						value: _RecipientInfo2.default.schema()
					})]
				}), _EncryptedContentInfo2.default.schema(names.encryptedContentInfo || {}), new asn1js.Constructed({
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

	return EnvelopedData;
}();
//**************************************************************************************


exports.default = EnvelopedData;
//# sourceMappingURL=EnvelopedData.js.map