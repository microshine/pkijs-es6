"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

var _Time = require("./Time");

var _Time2 = _interopRequireDefault(_Time);

var _PublicKeyInfo = require("./PublicKeyInfo");

var _PublicKeyInfo2 = _interopRequireDefault(_PublicKeyInfo);

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

var _Extensions = require("./Extensions");

var _Extensions2 = _interopRequireDefault(_Extensions);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************
function tbsCertificate() {
	var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

	//TBSCertificate  ::=  SEQUENCE  {
	//    version         [0]  EXPLICIT Version DEFAULT v1,
	//    serialNumber         CertificateSerialNumber,
	//    signature            AlgorithmIdentifier,
	//    issuer               Name,
	//    validity             Validity,
	//    subject              Name,
	//    subjectPublicKeyInfo SubjectPublicKeyInfo,
	//    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//                         -- If present, version MUST be v2 or v3
	//    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//                         -- If present, version MUST be v2 or v3
	//    extensions      [3]  EXPLICIT Extensions OPTIONAL
	//    -- If present, version MUST be v3
	//}

	/**
  * @type {Object}
  * @property {string} [blockName]
  * @property {string} [tbsCertificateVersion]
  * @property {string} [tbsCertificateSerialNumber]
  * @property {string} [signature]
  * @property {string} [issuer]
  * @property {string} [tbsCertificateValidity]
  * @property {string} [notBefore]
  * @property {string} [notAfter]
  * @property {string} [subject]
  * @property {string} [subjectPublicKeyInfo]
  * @property {string} [tbsCertificateIssuerUniqueID]
  * @property {string} [tbsCertificateSubjectUniqueID]
  * @property {string} [extensions]
  */
	var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

	return new asn1js.Sequence({
		name: names.blockName || "tbsCertificate",
		value: [new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 0 // [0]
			},
			value: [new asn1js.Integer({ name: names.tbsCertificateVersion || "tbsCertificate.version" }) // EXPLICIT integer value
			]
		}), new asn1js.Integer({ name: names.tbsCertificateSerialNumber || "tbsCertificate.serialNumber" }), _AlgorithmIdentifier2.default.schema(names.signature || {
			names: {
				blockName: "tbsCertificate.signature"
			}
		}), _RelativeDistinguishedNames2.default.schema(names.issuer || {
			names: {
				blockName: "tbsCertificate.issuer"
			}
		}), new asn1js.Sequence({
			name: names.tbsCertificateValidity || "tbsCertificate.validity",
			value: [_Time2.default.schema(names.notBefore || {
				names: {
					utcTimeName: "tbsCertificate.notBefore",
					generalTimeName: "tbsCertificate.notBefore"
				}
			}), _Time2.default.schema(names.notAfter || {
				names: {
					utcTimeName: "tbsCertificate.notAfter",
					generalTimeName: "tbsCertificate.notAfter"
				}
			})]
		}), _RelativeDistinguishedNames2.default.schema(names.subject || {
			names: {
				blockName: "tbsCertificate.subject"
			}
		}), _PublicKeyInfo2.default.schema(names.subjectPublicKeyInfo || {
			names: {
				blockName: "tbsCertificate.subjectPublicKeyInfo"
			}
		}), new asn1js.Primitive({
			name: names.tbsCertificateIssuerUniqueID || "tbsCertificate.issuerUniqueID",
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 1 // [1]
			}
		}), // IMPLICIT bistring value
		new asn1js.Primitive({
			name: names.tbsCertificateSubjectUniqueID || "tbsCertificate.subjectUniqueID",
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 2 // [2]
			}
		}), // IMPLICIT bistring value
		new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 3 // [3]
			},
			value: [_Extensions2.default.schema(names.extensions || {
				names: {
					blockName: "tbsCertificate.extensions"
				}
			})]
		}) // EXPLICIT SEQUENCE value
		]
	});
}
//**************************************************************************************

var Certificate = function () {
	//**********************************************************************************
	/**
  * Constructor for Certificate class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Certificate() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Certificate);

		//region Internal properties of the object
		/**
   * @type {ArrayBuffer}
   * @description tbs
   */
		this.tbs = (0, _pvutils.getParametersValue)(parameters, "tbs", Certificate.defaultValues("tbs"));
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", Certificate.defaultValues("version"));
		/**
   * @type {Integer}
   * @description serialNumber
   */
		this.serialNumber = (0, _pvutils.getParametersValue)(parameters, "serialNumber", Certificate.defaultValues("serialNumber"));
		/**
   * @type {AlgorithmIdentifier}
   * @description signature
   */
		this.signature = (0, _pvutils.getParametersValue)(parameters, "signature", Certificate.defaultValues("signature"));
		/**
   * @type {RelativeDistinguishedNames}
   * @description issuer
   */
		this.issuer = (0, _pvutils.getParametersValue)(parameters, "issuer", Certificate.defaultValues("issuer"));
		/**
   * @type {Time}
   * @description notBefore
   */
		this.notBefore = (0, _pvutils.getParametersValue)(parameters, "notBefore", Certificate.defaultValues("notBefore"));
		/**
   * @type {Time}
   * @description notAfter
   */
		this.notAfter = (0, _pvutils.getParametersValue)(parameters, "notAfter", Certificate.defaultValues("notAfter"));
		/**
   * @type {RelativeDistinguishedNames}
   * @description subject
   */
		this.subject = (0, _pvutils.getParametersValue)(parameters, "subject", Certificate.defaultValues("subject"));
		/**
   * @type {PublicKeyInfo}
   * @description subjectPublicKeyInfo
   */
		this.subjectPublicKeyInfo = (0, _pvutils.getParametersValue)(parameters, "subjectPublicKeyInfo", Certificate.defaultValues("subjectPublicKeyInfo"));

		if ("issuerUniqueID" in parameters)
			/**
    * @type {ArrayBuffer}
    * @description issuerUniqueID
    */
			this.issuerUniqueID = (0, _pvutils.getParametersValue)(parameters, "issuerUniqueID", Certificate.defaultValues("issuerUniqueID"));

		if ("subjectUniqueID" in parameters)
			/**
    * @type {ArrayBuffer}
    * @description subjectUniqueID
    */
			this.subjectUniqueID = (0, _pvutils.getParametersValue)(parameters, "subjectUniqueID", Certificate.defaultValues("subjectUniqueID"));

		if ("extensions" in parameters)
			/**
    * @type {Array}
    * @description extensions
    */
			this.extensions = (0, _pvutils.getParametersValue)(parameters, "extensions", Certificate.defaultValues("extensions"));

		/**
   * @type {AlgorithmIdentifier}
   * @description signatureAlgorithm
   */
		this.signatureAlgorithm = (0, _pvutils.getParametersValue)(parameters, "signatureAlgorithm", Certificate.defaultValues("signatureAlgorithm"));
		/**
   * @type {BitString}
   * @description signatureValue
   */
		this.signatureValue = (0, _pvutils.getParametersValue)(parameters, "signatureValue", Certificate.defaultValues("signatureValue"));
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


	_createClass(Certificate, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Certificate.schema({
				names: {
					tbsCertificate: {
						names: {
							extensions: {
								names: {
									extensions: "tbsCertificate.extensions"
								}
							}
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CERT");
			//endregion

			//region Get internal properties from parsed schema
			this.tbs = asn1.result.tbsCertificate.valueBeforeDecode;

			if ("tbsCertificate.version" in asn1.result) this.version = asn1.result["tbsCertificate.version"].valueBlock.valueDec;
			this.serialNumber = asn1.result["tbsCertificate.serialNumber"];
			this.signature = new _AlgorithmIdentifier2.default({ schema: asn1.result["tbsCertificate.signature"] });
			this.issuer = new _RelativeDistinguishedNames2.default({ schema: asn1.result["tbsCertificate.issuer"] });
			this.notBefore = new _Time2.default({ schema: asn1.result["tbsCertificate.notBefore"] });
			this.notAfter = new _Time2.default({ schema: asn1.result["tbsCertificate.notAfter"] });
			this.subject = new _RelativeDistinguishedNames2.default({ schema: asn1.result["tbsCertificate.subject"] });
			this.subjectPublicKeyInfo = new _PublicKeyInfo2.default({ schema: asn1.result["tbsCertificate.subjectPublicKeyInfo"] });
			if ("tbsCertificate.issuerUniqueID" in asn1.result) this.issuerUniqueID = asn1.result["tbsCertificate.issuerUniqueID"].valueBlock.valueHex;
			if ("tbsCertificate.subjectUniqueID" in asn1.result) this.issuerUniqueID = asn1.result["tbsCertificate.subjectUniqueID"].valueBlock.valueHex;
			if ("tbsCertificate.extensions" in asn1.result) this.extensions = Array.from(asn1.result["tbsCertificate.extensions"], function (element) {
				return new _Extension2.default({ schema: element });
			});

			this.signatureAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.signatureAlgorithm });
			this.signatureValue = asn1.result.signatureValue;
			//endregion
		}
		//**********************************************************************************
		/**
   * Create ASN.1 schema for existing values of TBS part for the certificate
   */

	}, {
		key: "encodeTBS",
		value: function encodeTBS() {
			//region Create array for output sequence
			var outputArray = [];

			if ("version" in this && this.version !== Certificate.defaultValues("version")) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Integer({ value: this.version }) // EXPLICIT integer value
					]
				}));
			}

			outputArray.push(this.serialNumber);
			outputArray.push(this.signature.toSchema());
			outputArray.push(this.issuer.toSchema());

			outputArray.push(new asn1js.Sequence({
				value: [this.notBefore.toSchema(), this.notAfter.toSchema()]
			}));

			outputArray.push(this.subject.toSchema());
			outputArray.push(this.subjectPublicKeyInfo.toSchema());

			if ("issuerUniqueID" in this) {
				outputArray.push(new asn1js.Primitive({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					valueHex: this.issuerUniqueID
				}));
			}
			if ("subjectUniqueID" in this) {
				outputArray.push(new asn1js.Primitive({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					valueHex: this.subjectUniqueID
				}));
			}

			if ("subjectUniqueID" in this) {
				outputArray.push(new asn1js.Primitive({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					value: [this.extensions.toSchema()]
				}));
			}

			if ("extensions" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.extensions, function (element) {
							return element.toSchema();
						})
					})]
				}));
			}
			//endregion

			//region Create and return output sequence
			return new asn1js.Sequence({
				value: outputArray
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
			var encodeFlag = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

			var tbsSchema = {};

			//region Decode stored TBS value
			if (encodeFlag === false) {
				if (this.tbs.length === 0) // No stored certificate TBS part
					return Certificate.schema().value[0];

				tbsSchema = asn1js.fromBER(this.tbs).result;
			}
			//endregion
			//region Create TBS schema via assembling from TBS parts
			else tbsSchema = this.encodeTBS();
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: [tbsSchema, this.signatureAlgorithm.toSchema(), this.signatureValue]
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
			var object = {
				tbs: (0, _pvutils.bufferToHexCodes)(this.tbs, 0, this.tbs.byteLength),
				serialNumber: this.serialNumber.toJSON(),
				signature: this.signature.toJSON(),
				issuer: this.issuer.toJSON(),
				notBefore: this.notBefore.toJSON(),
				notAfter: this.notAfter.toJSON(),
				subject: this.subject.toJSON(),
				subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
				signatureAlgorithm: this.signatureAlgorithm.toJSON(),
				signatureValue: this.signatureValue.toJSON()
			};

			if ("version" in this && this.version !== Certificate.defaultValues("version")) object.version = this.version;

			if ("issuerUniqueID" in this) object.issuerUniqueID = (0, _pvutils.bufferToHexCodes)(this.issuerUniqueID, 0, this.issuerUniqueID.byteLength);

			if ("subjectUniqueID" in this) object.subjectUniqueID = (0, _pvutils.bufferToHexCodes)(this.subjectUniqueID, 0, this.subjectUniqueID.byteLength);

			if ("extensions" in this) object.extensions = Array.from(this.extensions, function (element) {
				return element.toJSON();
			});

			return object;
		}
		//**********************************************************************************
		/**
   * Importing public key for current certificate
   */

	}, {
		key: "getPublicKey",
		value: function getPublicKey() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? null : arguments[0];

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Find correct algorithm for imported public key
			if (parameters === null) {
				//region Initial variables
				parameters = {};
				//endregion

				//region Find signer's hashing algorithm
				var shaAlgorithm = (0, _common.getHashAlgorithm)(this.signatureAlgorithm);
				if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
				//endregion

				//region Get information about public key algorithm and default parameters for import
				var algorithmObject = (0, _common.getAlgorithmByOID)(this.subjectPublicKeyInfo.algorithm.algorithmId);
				if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + this.subjectPublicKeyInfo.algorithm.algorithmId);

				parameters.algorithm = (0, _common.getAlgorithmParameters)(algorithmObject.name, "importkey");
				if ("hash" in parameters.algorithm.algorithm) parameters.algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion
			}
			//endregion

			//region Get neccessary values from internal fields for current certificate
			var publicKeyInfoSchema = this.subjectPublicKeyInfo.toSchema();
			var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
			var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);
			//endregion

			return crypto.importKey("spki", publicKeyInfoView, parameters.algorithm.algorithm, true, parameters.algorithm.usages);
		}
		//**********************************************************************************
		/**
   * Get SHA-1 hash value for subject public key
   */

	}, {
		key: "getKeyHash",
		value: function getKeyHash() {
			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			return crypto.digest({ name: "sha-1" }, new Uint8Array(this.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
		}
		//**********************************************************************************
		/**
   * Make a signature for current value from TBS section
   * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {string} [hashAlgorithm="SHA-1"] Hashing algorithm
   */

	}, {
		key: "sign",
		value: function sign(privateKey) {
			var _this = this;

			var hashAlgorithm = arguments.length <= 1 || arguments[1] === undefined ? "SHA-1" : arguments[1];

			//region Get hashing algorithm
			var oid = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
			if (oid === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);
			//endregion

			//region Get a "default parameters" for current algorithm
			var defParams = (0, _common.getAlgorithmParameters)(privateKey.algorithm.name, "sign");
			defParams.algorithm.hash.name = hashAlgorithm;
			//endregion

			//region Fill internal structures base on "privateKey" and "hashAlgorithm"
			switch (privateKey.algorithm.name.toUpperCase()) {
				case "RSASSA-PKCS1-V1_5":
				case "ECDSA":
					this.signature.algorithmId = (0, _common.getOIDByAlgorithm)(defParams.algorithm);
					this.signatureAlgorithm.algorithmId = this.signature.algorithmId;
					break;
				case "RSA-PSS":
					{
						//region Set "saltLength" as a length (in octets) of hash function result
						switch (hashAlgorithm.toUpperCase()) {
							case "SHA-256":
								defParams.algorithm.saltLength = 32;
								break;
							case "SHA-384":
								defParams.algorithm.saltLength = 48;
								break;
							case "SHA-512":
								defParams.algorithm.saltLength = 64;
								break;
							default:
						}
						//endregion

						//region Fill "RSASSA_PSS_params" object
						var paramsObject = {};

						if (hashAlgorithm.toUpperCase() !== "SHA-1") {
							var hashAlgorithmOID = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
							if (hashAlgorithmOID === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);

							paramsObject.hashAlgorithm = new _AlgorithmIdentifier2.default({
								algorithmId: hashAlgorithmOID,
								algorithmParams: new asn1js.Null()
							});

							paramsObject.maskGenAlgorithm = new _AlgorithmIdentifier2.default({
								algorithmId: "1.2.840.113549.1.1.8", // MGF1
								algorithmParams: paramsObject.hashAlgorithm.toSchema()
							});
						}

						if (defParams.algorithm.saltLength !== 20) paramsObject.saltLength = defParams.algorithm.saltLength;

						var pssParameters = new _RSASSAPSSParams2.default(paramsObject);
						//endregion

						//region Automatically set signature algorithm
						this.signature = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.113549.1.1.10",
							algorithmParams: pssParameters.toSchema()
						});
						this.signatureAlgorithm = this.signature; // Must be the same
						//endregion
					}
					break;
				default:
					return Promise.reject("Unsupported signature algorithm: " + privateKey.algorithm.name);
			}
			//endregion

			//region Create TBS data for signing
			this.tbs = this.encodeTBS().toBER(false);
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Signing TBS data on provided private key
			return crypto.sign(defParams.algorithm, privateKey, new Uint8Array(this.tbs)).then(function (result) {
				//region Special case for ECDSA algorithm
				if (defParams.algorithm.name === "ECDSA") result = (0, _common.createCMSECDSASignature)(result);
				//endregion

				_this.signatureValue = new asn1js.BitString({ valueHex: result });
			}, function (error) {
				return Promise.reject("Signing error: " + error);
			});
			//endregion
		}
		//**********************************************************************************

	}, {
		key: "verify",
		value: function verify() {
			var _this2 = this;

			var issuerCertificate = arguments.length <= 0 || arguments[0] === undefined ? null : arguments[0];

			//region Global variables
			var sequence = Promise.resolve();

			var subjectPublicKeyInfo = {};

			var signature = this.signatureValue;
			var tbs = this.tbs;
			//endregion

			//region Set correct "subjectPublicKeyInfo" value
			if (issuerCertificate !== null) subjectPublicKeyInfo = issuerCertificate.subjectPublicKeyInfo;else {
				if (this.issuer.isEqual(this.subject)) // Self-signed certificate
					subjectPublicKeyInfo = this.subjectPublicKeyInfo;
			}

			if (subjectPublicKeyInfo instanceof _PublicKeyInfo2.default === false) return Promise.reject("Please provide issuer certificate as a parameter");
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Find signer's hashing algorithm
			var shaAlgorithm = (0, _common.getHashAlgorithm)(this.signatureAlgorithm);
			if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
			//endregion

			//region Importing public key
			sequence = sequence.then(function () {
				//region Get information about public key algorithm and default parameters for import
				var algorithmId = void 0;
				if (_this2.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = _this2.signatureAlgorithm.algorithmId;else algorithmId = subjectPublicKeyInfo.algorithm.algorithmId;

				var algorithmObject = (0, _common.getAlgorithmByOID)(algorithmId);
				if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + algorithmId);

				var algorithm = (0, _common.getAlgorithmParameters)(algorithmObject.name, "importkey");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion

				var publicKeyInfoSchema = subjectPublicKeyInfo.toSchema();
				var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
				var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

				return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
			});
			//endregion

			//region Verify signature for the certificate
			sequence = sequence.then(function (publicKey) {
				//region Get default algorithm parameters for verification
				var algorithm = (0, _common.getAlgorithmParameters)(publicKey.algorithm.name, "verify");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion

				//region Special case for ECDSA signatures
				var signatureValue = signature.valueBlock.valueHex;

				if (publicKey.algorithm.name === "ECDSA") {
					var asn1 = asn1js.fromBER(signatureValue);
					signatureValue = (0, _common.createECDSASignatureFromCMS)(asn1.result);
				}
				//endregion

				//region Special case for RSA-PSS
				if (publicKey.algorithm.name === "RSA-PSS") {
					var pssParameters = void 0;

					try {
						pssParameters = new _RSASSAPSSParams2.default({ schema: _this2.signatureAlgorithm.algorithmParams });
					} catch (ex) {
						return Promise.reject(ex);
					}

					if ("saltLength" in pssParameters) algorithm.algorithm.saltLength = pssParameters.saltLength;else algorithm.algorithm.saltLength = 20;

					var hashAlgo = "SHA-1";

					if ("hashAlgorithm" in pssParameters) {
						var hashAlgorithm = (0, _common.getAlgorithmByOID)(pssParameters.hashAlgorithm.algorithmId);
						if ("name" in hashAlgorithm === false) return Promise.reject("Unrecognized hash algorithm: " + pssParameters.hashAlgorithm.algorithmId);

						hashAlgo = hashAlgorithm.name;
					}

					algorithm.algorithm.hash.name = hashAlgo;
				}
				//endregion

				return crypto.verify(algorithm.algorithm, publicKey, new Uint8Array(signatureValue), new Uint8Array(tbs));
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "tbs":
					return new ArrayBuffer(0);
				case "version":
					return 0;
				case "serialNumber":
					return new asn1js.Integer();
				case "signature":
					return new _AlgorithmIdentifier2.default();
				case "issuer":
					return new _RelativeDistinguishedNames2.default();
				case "notBefore":
					return new _Time2.default();
				case "notAfter":
					return new _Time2.default();
				case "subject":
					return new _RelativeDistinguishedNames2.default();
				case "subjectPublicKeyInfo":
					return new _PublicKeyInfo2.default();
				case "issuerUniqueID":
					return new ArrayBuffer(0);
				case "subjectUniqueID":
					return new ArrayBuffer(0);
				case "extensions":
					return [];
				case "signatureAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signatureValue":
					return new asn1js.BitString();
				default:
					throw new Error("Invalid member name for Certificate class: " + memberName);
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

			//Certificate  ::=  SEQUENCE  {
			//    tbsCertificate       TBSCertificate,
			//    signatureAlgorithm   AlgorithmIdentifier,
			//    signatureValue       BIT STRING  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [tbsCertificate]
    * @property {string} [signatureAlgorithm]
    * @property {string} [signatureValue]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [tbsCertificate(names.tbsCertificate), _AlgorithmIdentifier2.default.schema(names.signatureAlgorithm || {
					names: {
						blockName: "signatureAlgorithm"
					}
				}), new asn1js.BitString({ name: names.signatureValue || "signatureValue" })]
			});
		}
	}]);

	return Certificate;
}();
//**************************************************************************************


exports.default = Certificate;
//# sourceMappingURL=Certificate.js.map