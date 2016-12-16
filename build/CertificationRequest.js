"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _PublicKeyInfo = require("./PublicKeyInfo");

var _PublicKeyInfo2 = _interopRequireDefault(_PublicKeyInfo);

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************
function CertificationRequestInfo() {
	var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

	//CertificationRequestInfo ::= SEQUENCE {
	//    version       INTEGER { v1(0) } (v1,...),
	//    subject       Name,
	//    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	//    attributes    [0] Attributes{{ CRIAttributes }}
	//}

	/**
  * @type {Object}
  * @property {string} [blockName]
  * @property {string} [CertificationRequestInfo]
  * @property {string} [CertificationRequestInfoVersion]
  * @property {string} [subject]
  * @property {string} [CertificationRequestInfoAttributes]
  * @property {string} [attributes]
  */
	var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

	return new asn1js.Sequence({
		name: names.CertificationRequestInfo || "CertificationRequestInfo",
		value: [new asn1js.Integer({ name: names.CertificationRequestInfoVersion || "CertificationRequestInfo.version" }), _RelativeDistinguishedNames2.default.schema(names.subject || {
			names: {
				blockName: "CertificationRequestInfo.subject"
			}
		}), _PublicKeyInfo2.default.schema({
			names: {
				blockName: "CertificationRequestInfo.subjectPublicKeyInfo"
			}
		}), new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 0 // [0]
			},
			value: [new asn1js.Repeated({
				optional: true, // Because OpenSSL makes wrong "attributes" field
				name: names.CertificationRequestInfoAttributes || "CertificationRequestInfo.attributes",
				value: _Attribute2.default.schema(names.attributes || {})
			})]
		})]
	});
}
//**************************************************************************************

var CertificationRequest = function () {
	//**********************************************************************************
	/**
  * Constructor for Attribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertificationRequest() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertificationRequest);

		//region Internal properties of the object
		/**
   * @type {ArrayBuffer}
   * @description tbs
   */
		this.tbs = (0, _pvutils.getParametersValue)(parameters, "tbs", CertificationRequest.defaultValues("tbs"));
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", CertificationRequest.defaultValues("version"));
		/**
   * @type {RelativeDistinguishedNames}
   * @description subject
   */
		this.subject = (0, _pvutils.getParametersValue)(parameters, "subject", CertificationRequest.defaultValues("subject"));
		/**
   * @type {PublicKeyInfo}
   * @description subjectPublicKeyInfo
   */
		this.subjectPublicKeyInfo = (0, _pvutils.getParametersValue)(parameters, "subjectPublicKeyInfo", CertificationRequest.defaultValues("subjectPublicKeyInfo"));

		if ("attributes" in parameters)
			/**
    * @type {Array.<Attribute>}
    * @description attributes
    */
			this.attributes = (0, _pvutils.getParametersValue)(parameters, "attributes", CertificationRequest.defaultValues("attributes"));

		/**
   * @type {AlgorithmIdentifier}
   * @description signatureAlgorithm
   */
		this.signatureAlgorithm = (0, _pvutils.getParametersValue)(parameters, "signatureAlgorithm", CertificationRequest.defaultValues("signatureAlgorithm"));
		/**
   * @type {BitString}
   * @description signatureAlgorithm
   */
		this.signatureValue = (0, _pvutils.getParametersValue)(parameters, "signatureValue", CertificationRequest.defaultValues("signatureValue"));
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


	_createClass(CertificationRequest, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertificationRequest.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PKCS10");
			//endregion

			//region Get internal properties from parsed schema
			this.tbs = asn1.result.CertificationRequestInfo.valueBeforeDecode;

			this.version = asn1.result["CertificationRequestInfo.version"].valueBlock.valueDec;
			this.subject = new _RelativeDistinguishedNames2.default({ schema: asn1.result["CertificationRequestInfo.subject"] });
			this.subjectPublicKeyInfo = new _PublicKeyInfo2.default({ schema: asn1.result["CertificationRequestInfo.subjectPublicKeyInfo"] });
			if ("CertificationRequestInfo.attributes" in asn1.result) this.attributes = Array.from(asn1.result["CertificationRequestInfo.attributes"], function (element) {
				return new _Attribute2.default({ schema: element });
			});

			this.signatureAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.signatureAlgorithm });
			this.signatureValue = asn1.result.signatureValue;
			//endregion
		}
		//**********************************************************************************
		/**
   * Aux function making ASN1js Sequence from current TBS
   * @returns {Sequence}
   */

	}, {
		key: "encodeTBS",
		value: function encodeTBS() {
			//region Create array for output sequence
			var outputArray = [new asn1js.Integer({ value: this.version }), this.subject.toSchema(), this.subjectPublicKeyInfo.toSchema()];

			if ("attributes" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: Array.from(this.attributes, function (element) {
						return element.toSchema();
					})
				}));
			}
			//endregion

			return new asn1js.Sequence({
				value: outputArray
			});
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

			//region Decode stored TBS value
			var tbsSchema = void 0;

			if (encodeFlag === false) {
				if (this.tbs.length === 0) // No stored TBS part
					return CertificationRequest.schema();

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
				version: this.version,
				subject: this.subject.toJSON(),
				subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
				signatureAlgorithm: this.signatureAlgorithm.toJSON(),
				signatureValue: this.signatureValue.toJSON()
			};

			if ("attributes" in this) object.attributes = Array.from(this.attributes, function (element) {
				return element.toJSON();
			});

			return object;
		}
		//**********************************************************************************
		/**
   * Makes signature for currect certification request
   * @param {Object} privateKey WebCrypto private key
   * @param {string} [hashAlgorithm=SHA-1] String representing current hashing algorithm
   */

	}, {
		key: "sign",
		value: function sign(privateKey) {
			var _this = this;

			var hashAlgorithm = arguments.length <= 1 || arguments[1] === undefined ? "SHA-1" : arguments[1];

			//region Get a private key from function parameter
			if (typeof privateKey === "undefined") return Promise.reject("Need to provide a private key for signing");
			//endregion

			//region Get hashing algorithm
			var oid = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
			if (oid === "") return Promise.reject("Unsupported hash algorithm: {$hashAlgorithm}");
			//endregion

			//region Get a "default parameters" for current algorithm
			var defParams = (0, _common.getAlgorithmParameters)(privateKey.algorithm.name, "sign");
			defParams.algorithm.hash.name = hashAlgorithm;
			//endregion

			//region Fill internal structures base on "privateKey" and "hashAlgorithm"
			switch (privateKey.algorithm.name.toUpperCase()) {
				case "RSASSA-PKCS1-V1_5":
				case "ECDSA":
					this.signatureAlgorithm.algorithmId = (0, _common.getOIDByAlgorithm)(defParams.algorithm);
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
						this.signatureAlgorithm = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.113549.1.1.10",
							algorithmParams: pssParameters.toSchema()
						});
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
		/**
   * Verify existing certification request signature
   * @returns {*}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this2 = this;

			//region Global variables
			var sequence = Promise.resolve();

			var subjectPublicKeyInfo = this.subjectPublicKeyInfo;
			var signature = this.signatureValue;
			var tbs = this.tbs;
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Find a correct hashing algorithm
			var shaAlgorithm = (0, _common.getHashAlgorithm)(this.signatureAlgorithm);
			if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
			//endregion

			//region Importing public key
			sequence = sequence.then(function () {
				//region Get information about public key algorithm and default parameters for import
				var algorithmId = void 0;
				if (_this2.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = _this2.signatureAlgorithm.algorithmId;else algorithmId = _this2.subjectPublicKeyInfo.algorithm.algorithmId;

				var algorithmObject = (0, _common.getAlgorithmByOID)(algorithmId);
				if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + algorithmId);

				var algorithmName = algorithmObject.name;

				var algorithm = (0, _common.getAlgorithmParameters)(algorithmName, "importkey");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion

				var publicKeyInfoSchema = subjectPublicKeyInfo.toSchema();
				var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
				var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

				return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
			});
			//endregion

			//region Verify signature
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
				case "subject":
					return new _RelativeDistinguishedNames2.default();
				case "subjectPublicKeyInfo":
					return new _PublicKeyInfo2.default();
				case "attributes":
					return [];
				case "signatureAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signatureValue":
					return new asn1js.BitString();
				default:
					throw new Error("Invalid member name for CertificationRequest class: " + memberName);
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

			//CertificationRequest ::= SEQUENCE {
			//    certificationRequestInfo CertificationRequestInfo,
			//    signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
			//    signature                BIT STRING
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [certificationRequestInfo]
    * @property {string} [signatureAlgorithm]
    * @property {string} [signatureValue]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				value: [CertificationRequestInfo(names.certificationRequestInfo || {}), new asn1js.Sequence({
					name: names.signatureAlgorithm || "signatureAlgorithm",
					value: [new asn1js.ObjectIdentifier(), new asn1js.Any({ optional: true })]
				}), new asn1js.BitString({ name: names.signatureValue || "signatureValue" })]
			});
		}
	}]);

	return CertificationRequest;
}();
//**************************************************************************************


exports.default = CertificationRequest;
//# sourceMappingURL=CertificationRequest.js.map