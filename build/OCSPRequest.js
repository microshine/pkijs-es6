"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _TBSRequest = require("./TBSRequest");

var _TBSRequest2 = _interopRequireDefault(_TBSRequest);

var _Signature = require("./Signature");

var _Signature2 = _interopRequireDefault(_Signature);

var _Request = require("./Request");

var _Request2 = _interopRequireDefault(_Request);

var _CertID = require("./CertID");

var _CertID2 = _interopRequireDefault(_CertID);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var OCSPRequest = function () {
	//**********************************************************************************
	/**
  * Constructor for OCSPRequest class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OCSPRequest() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OCSPRequest);

		//region Internal properties of the object
		/**
   * @type {TBSRequest}
   * @description tbsRequest
   */
		this.tbsRequest = (0, _pvutils.getParametersValue)(parameters, "tbsRequest", OCSPRequest.defaultValues("tbsRequest"));

		if ("optionalSignature" in parameters)
			/**
    * @type {Signature}
    * @description optionalSignature
    */
			this.optionalSignature = (0, _pvutils.getParametersValue)(parameters, "optionalSignature", OCSPRequest.defaultValues("optionalSignature"));
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


	_createClass(OCSPRequest, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OCSPRequest.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OCSP_REQUEST");
			//endregion

			//region Get internal properties from parsed schema
			this.tbsRequest = new _TBSRequest2.default({ schema: asn1.result.tbsRequest });
			if ("optionalSignature" in asn1.result) this.optionalSignature = new _Signature2.default({ schema: asn1.result.optionalSignature });
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @param {boolean} encodeFlag If param equal to false then create TBS schema via decoding stored value. In othe case create TBS schema via assembling from TBS parts.
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			var encodeFlag = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(this.tbsRequest.toSchema(encodeFlag));
			if ("optionalSignature" in this) outputArray.push(this.optionalSignature.toSchema());
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
				tbsRequest: this.tbsRequest.toJSON()
			};

			if ("optionalSignature" in this) _object.optionalSignature = this.optionalSignature.toJSON();

			return _object;
		}
		//**********************************************************************************
		/**
   * Making OCSP Request for specific certificate
   * @param {Certificate} certificate Certificate making OCSP Request for
   * @param {Object} parameters Additional parameters
   * @returns {Promise}
   */

	}, {
		key: "createForCertificate",
		value: function createForCertificate(certificate, parameters) {
			var _this = this;

			//region Initial variables
			var sequence = Promise.resolve();

			var certID = new _CertID2.default();
			//endregion

			//region Create OCSP certificate identifier for the certificate
			sequence = sequence.then(function () {
				return certID.createForCertificate(certificate, parameters);
			});
			//endregion

			//region Make final request data
			sequence = sequence.then(function () {
				_this.tbsRequest = new _TBSRequest2.default({
					requestList: [new _Request2.default({
						reqCert: certID
					})]
				});
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************
		/**
   * Make signature for current OCSP Request
   * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {string} [hashAlgorithm] Hashing algorithm. Default SHA-1
   * @returns {Promise}
   */

	}, {
		key: "sign",
		value: function sign(privateKey, hashAlgorithm) {
			var _this2 = this;

			//region Get a private key from function parameter
			if (typeof privateKey === "undefined") return Promise.reject("Need to provide a private key for signing");
			//endregion

			//region Get hashing algorithm
			if (typeof hashAlgorithm === "undefined") hashAlgorithm = "SHA-1";else {
				//region Simple check for supported algorithm
				var oid = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
				if (oid === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);
				//endregion
			}
			//endregion

			//region Check that "optionalSignature" exists in the current request
			if ("optionalSignature" in this === false) return Promise.reject("Need to create \"optionalSignature\" field before signing");
			//endregion

			//region Get a "default parameters" for current algorithm
			var defParams = (0, _common.getAlgorithmParameters)(privateKey.algorithm.name, "sign");
			defParams.algorithm.hash.name = hashAlgorithm;
			//endregion

			//region Fill internal structures base on "privateKey" and "hashAlgorithm"
			switch (privateKey.algorithm.name.toUpperCase()) {
				case "RSASSA-PKCS1-V1_5":
				case "ECDSA":
					this.optionalSignature.signatureAlgorithm.algorithmId = (0, _common.getOIDByAlgorithm)(defParams.algorithm);
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
						this.optionalSignature.signatureAlgorithm = new _AlgorithmIdentifier2.default({
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
			var tbs = this.tbsRequest.toSchema(true).toBER(false);
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Signing TBS data on provided private key
			return crypto.sign(defParams.algorithm, privateKey, new Uint8Array(tbs)).then(function (result) {
				//region Special case for ECDSA algorithm
				if (defParams.algorithm.name === "ECDSA") result = (0, _common.createCMSECDSASignature)(result);
				//endregion

				_this2.optionalSignature.signature = new asn1js.BitString({ valueHex: result });
			}, function (error) {
				return Promise.reject("Signing error: " + error);
			});
			//endregion
		}
		//**********************************************************************************

	}, {
		key: "verify",
		value: function verify() {}
		// TODO: Create the function

		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "tbsRequest":
					return new _TBSRequest2.default();
				case "optionalSignature":
					return new _Signature2.default();
				default:
					throw new Error("Invalid member name for OCSPRequest class: " + memberName);
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
				case "tbsRequest":
					return _TBSRequest2.default.compareWithDefault("tbs", memberValue.tbs) && _TBSRequest2.default.compareWithDefault("version", memberValue.version) && _TBSRequest2.default.compareWithDefault("requestorName", memberValue.requestorName) && _TBSRequest2.default.compareWithDefault("requestList", memberValue.requestList) && _TBSRequest2.default.compareWithDefault("requestExtensions", memberValue.requestExtensions);
				case "optionalSignature":
					return _Signature2.default.compareWithDefault("signatureAlgorithm", memberValue.signatureAlgorithm) && _Signature2.default.compareWithDefault("signature", memberValue.signature) && _Signature2.default.compareWithDefault("certs", memberValue.certs);
				default:
					throw new Error("Invalid member name for OCSPRequest class: " + memberName);
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

			//OCSPRequest     ::=     SEQUENCE {
			//    tbsRequest                  TBSRequest,
			//    optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [tbsRequest]
    * @property {string} [optionalSignature]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "OCSPRequest",
				value: [_TBSRequest2.default.schema(names.tbsRequest || {
					names: {
						blockName: "tbsRequest"
					}
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [_Signature2.default.schema(names.optionalSignature || {
						names: {
							blockName: "optionalSignature"
						}
					})]
				})]
			});
		}
	}]);

	return OCSPRequest;
}();
//**************************************************************************************


exports.default = OCSPRequest;
//# sourceMappingURL=OCSPRequest.js.map