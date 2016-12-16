"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _ContentInfo = require("./ContentInfo");

var _ContentInfo2 = _interopRequireDefault(_ContentInfo);

var _MacData = require("./MacData");

var _MacData2 = _interopRequireDefault(_MacData);

var _DigestInfo = require("./DigestInfo");

var _DigestInfo2 = _interopRequireDefault(_DigestInfo);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _SignedData = require("./SignedData");

var _SignedData2 = _interopRequireDefault(_SignedData);

var _EncapsulatedContentInfo = require("./EncapsulatedContentInfo");

var _EncapsulatedContentInfo2 = _interopRequireDefault(_EncapsulatedContentInfo);

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _SignerInfo = require("./SignerInfo");

var _SignerInfo2 = _interopRequireDefault(_SignerInfo);

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

var _SignedAndUnsignedAttributes = require("./SignedAndUnsignedAttributes");

var _SignedAndUnsignedAttributes2 = _interopRequireDefault(_SignedAndUnsignedAttributes);

var _AuthenticatedSafe = require("./AuthenticatedSafe");

var _AuthenticatedSafe2 = _interopRequireDefault(_AuthenticatedSafe);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var PFX = function () {
	//**********************************************************************************
	/**
  * Constructor for PFX class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PFX() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PFX);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", PFX.defaultValues("version"));
		/**
   * @type {ContentInfo}
   * @description authSafe
   */
		this.authSafe = (0, _pvutils.getParametersValue)(parameters, "authSafe", PFX.defaultValues("authSafe"));

		if ("macData" in parameters) {
			/**
    * @type {MacData}
    * @description macData
    */
			this.macData = (0, _pvutils.getParametersValue)(parameters, "macData", PFX.defaultValues("macData"));
		}

		if ("parsedValue" in parameters) {
			/**
    * @type {*}
    * @description parsedValue
    */
			this.parsedValue = (0, _pvutils.getParametersValue)(parameters, "parsedValue", PFX.defaultValues("parsedValue"));
		}
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


	_createClass(PFX, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PFX.schema({
				names: {
					version: "version",
					authSafe: {
						names: {
							blockName: "authSafe"
						}
					},
					macData: {
						names: {
							blockName: "macData"
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PFX");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;
			this.authSafe = new _ContentInfo2.default({ schema: asn1.result.authSafe });

			if ("macData" in asn1.result) this.macData = new _MacData2.default({ schema: asn1.result.macData });
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
			//region Construct and return new ASN.1 schema for this object
			var outputArray = [new asn1js.Integer({ value: this.version }), this.authSafe.toSchema()];

			if ("macData" in this) outputArray.push(this.macData.toSchema());

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
			var output = {
				version: this.version,
				authSafe: this.authSafe.toJSON()
			};

			if ("macData" in this) output.macData = this.macData.toJSON();

			return output;
		}
		//**********************************************************************************
		/**
   * Making ContentInfo from "parsedValue" object
   * @param {Object} parameters Parameters, specific to each "integrity mode"
   */

	}, {
		key: "makeInternalValues",
		value: function makeInternalValues() {
			var _this = this;

			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//region Check mandatory parameter
			if (parameters instanceof Object == false) return Promise.reject("The \"parameters\" must has \"Object\" type");

			if ("parsedValue" in this == false) return Promise.reject("Please call \"parseValues\" function first in order to make \"parsedValue\" data");

			if ("integrityMode" in this.parsedValue == false) return Promise.reject("Absent mandatory parameter \"integrityMode\" inside \"parsedValue\"");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Makes values for each particular integrity mode
			//region Check that we do have neccessary fields in "parsedValue" object
			if ("authenticatedSafe" in this.parsedValue == false) return Promise.reject("Absent mandatory parameter \"authenticatedSafe\" in \"parsedValue\"");
			//endregion

			switch (this.parsedValue.integrityMode) {
				//region HMAC-based integrity
				case 0:
					{
						var _ret = function () {
							//region Check additional mandatory parameters
							if ("iterations" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"iterations\"")
								};

							if ("pbkdf2HashAlgorithm" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"pbkdf2HashAlgorithm\"")
								};

							if ("hmacHashAlgorithm" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"hmacHashAlgorithm\"")
								};

							if ("password" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"password\"")
								};
							//endregion

							//region Initial variables
							var saltBuffer = new ArrayBuffer(64);
							var saltView = new Uint8Array(saltBuffer);

							(0, _common.getRandomValues)(saltView);

							var length = void 0;

							//region Choose correct length for HMAC key
							switch (parameters.hmacHashAlgorithm.toLowerCase()) {
								case "sha-1":
									length = 160;
									break;
								case "sha-256":
									length = 256;
									break;
								case "sha-384":
									length = 384;
									break;
								case "sha-512":
									length = 512;
									break;
								default:
									return {
										v: Promise.reject("Incorrect \"parameters.hmacHashAlgorithm\" parameter: " + parameters.hmacHashAlgorithm)
									};
							}
							//endregion

							var hmacAlgorithm = {
								name: "HMAC",
								length: length,
								hash: {
									name: parameters.hmacHashAlgorithm
								}
							};
							//endregion

							//region Generate HMAC key using PBKDF2
							//region Derive PBKDF2 key from "password" buffer
							sequence = sequence.then(function () {
								var passwordView = new Uint8Array(parameters.password);

								return crypto.importKey("raw", passwordView, "PBKDF2", true, ['deriveKey']);
							}, function (error) {
								return Promise.reject(error);
							});
							//endregion

							//region Derive key for HMAC
							sequence = sequence.then(function (result) {
								return crypto.deriveKey({
									name: "PBKDF2",
									hash: {
										name: parameters.pbkdf2HashAlgorithm
									},
									salt: saltView,
									iterations: parameters.iterations
								}, result, hmacAlgorithm, true, ['sign']);
							}, function (error) {
								return Promise.reject(error);
							});
							//endregion
							//endregion

							//region Make final "MacData" value
							//region Make signed HMAC value
							sequence = sequence.then(function (result) {
								_this.authSafe = new _ContentInfo2.default({
									contentType: "1.2.840.113549.1.7.1",
									content: new asn1js.OctetString({ valueHex: _this.parsedValue.authenticatedSafe.toSchema().toBER(false) })
								});

								var data = _this.authSafe.content.toBER(false);
								var view = new Uint8Array(data);

								return crypto.sign(hmacAlgorithm, result, view);
							}, function (error) {
								return Promise.reject(error);
							});
							//endregion

							//region Make "MacData" values
							sequence = sequence.then(function (result) {
								_this.macData = new _MacData2.default({
									mac: new _DigestInfo2.default({
										digestAlgorithm: new _AlgorithmIdentifier2.default({
											algorithmId: (0, _common.getOIDByAlgorithm)({ name: parameters.hmacHashAlgorithm })
										}),
										digest: new asn1js.OctetString({ valueHex: result })
									}),
									macSalt: new asn1js.OctetString({ valueHex: saltBuffer }),
									iterations: parameters.iterations
								});
							}, function (error) {
								return Promise.reject(error);
							});
							//endregion
							//endregion
						}();

						if ((typeof _ret === "undefined" ? "undefined" : _typeof(_ret)) === "object") return _ret.v;
					}
					break;
				//endregion
				//region publicKey-based integrity
				case 1:
					{
						var _ret2 = function () {
							//region Check additional mandatory parameters
							if ("signingCertificate" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"signingCertificate\"")
								};

							if ("privateKey" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"privateKey\"")
								};

							if ("hashAlgorithm" in parameters == false) return {
									v: Promise.reject("Absent mandatory parameter \"hashAlgorithm\"")
								};
							//endregion

							//region Making data to be signed
							// NOTE: all internal data for "authenticatedSafe" must be already prepared.
							// Thus user must call "makeValues" for all internal "SafeContent" value with appropriate parameters.
							// Or user can choose to use values from initial parsing of existing PKCS#12 data.

							var toBeSigned = _this.parsedValue.authenticatedSafe.toSchema().toBER(false);
							//endregion

							//region Initial variables
							var cmsSigned = new _SignedData2.default({
								version: 1,
								encapContentInfo: new _EncapsulatedContentInfo2.default({
									eContentType: "1.2.840.113549.1.7.1", // "data" content type
									eContent: new asn1js.OctetString({ valueHex: toBeSigned })
								}),
								certificates: [parameters.signingCertificate]
							});
							//endregion

							//region Making additional attributes for CMS Signed Data
							//region Create a message digest
							sequence = sequence.then(function () {
								return crypto.digest({ name: parameters.hashAlgorithm }, new Uint8Array(toBeSigned));
							});
							//endregion

							//region Combine all signed extensions
							sequence = sequence.then(function (result) {
								//region Initial variables
								var signedAttr = [];
								//endregion

								//region contentType
								signedAttr.push(new _Attribute2.default({
									type: "1.2.840.113549.1.9.3",
									values: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })]
								}));
								//endregion
								//region signingTime
								signedAttr.push(new _Attribute2.default({
									type: "1.2.840.113549.1.9.5",
									values: [new asn1js.UTCTime({ valueDate: new Date() })]
								}));
								//endregion
								//region messageDigest
								signedAttr.push(new _Attribute2.default({
									type: "1.2.840.113549.1.9.4",
									values: [new asn1js.OctetString({ valueHex: result })]
								}));
								//endregion

								//region Making final value for "SignerInfo" type
								cmsSigned.signerInfos.push(new _SignerInfo2.default({
									version: 1,
									sid: new _IssuerAndSerialNumber2.default({
										issuer: parameters.signingCertificate.issuer,
										serialNumber: parameters.signingCertificate.serialNumber
									}),
									signedAttrs: new _SignedAndUnsignedAttributes2.default({
										type: 0,
										attributes: signedAttr
									})
								}));
								//endregion
							}, function (error) {
								return Promise.reject("Error during making digest for message: " + error);
							});
							//endregion
							//endregion

							//region Signing CMS Signed Data
							sequence = sequence.then(function () {
								return cmsSigned.sign(parameters.privateKey, 0, parameters.hashAlgorithm);
							});
							//endregion

							//region Making final CMS_CONTENT_INFO type
							sequence = sequence.then(function () {
								_this.authSafe = new _ContentInfo2.default({
									contentType: "1.2.840.113549.1.7.2",
									content: cmsSigned.toSchema(true)
								});
							}, function (error) {
								return Promise.reject("Error during making signature: " + error);
							});
							//endregion
						}();

						if ((typeof _ret2 === "undefined" ? "undefined" : _typeof(_ret2)) === "object") return _ret2.v;
					}
					break;
				//endregion
				//region default
				default:
					return Promise.reject("Parameter \"integrityMode\" has unknown value: " + parameters.integrityMode);
				//endregion
			}
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}, {
		key: "parseInternalValues",
		value: function parseInternalValues(parameters) {
			var _this2 = this;

			//region Check input data from "parameters"
			if (parameters instanceof Object == false) return Promise.reject("The \"parameters\" must has \"Object\" type");

			if ("checkIntegrity" in parameters == false) parameters.checkIntegrity = true;
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Create value for "this.parsedValue.authenticatedSafe" and check integrity
			this.parsedValue = {};

			switch (this.authSafe.contentType) {
				//region data
				case "1.2.840.113549.1.7.1":
					{
						//region Check additional mandatory parameters
						if ("password" in parameters == false) return Promise.reject("Absent mandatory parameter \"password\"");
						//endregion

						//region Integrity based on HMAC
						this.parsedValue.integrityMode = 0;
						//endregion

						//region Check that we do have OCTETSTRING as "content"
						if (this.authSafe.content instanceof asn1js.OctetString == false) return Promise.reject("Wrong type of \"this.authSafe.content\"");
						//endregion

						//region Parse internal ASN.1 data
						var asn1 = asn1js.fromBER(this.authSafe.content.valueBlock.valueHex);
						if (asn1.offset == -1) return Promise.reject("Error during parsing of ASN.1 data inside \"this.authSafe.content\"");
						//endregion

						//region Set "authenticatedSafe" value
						this.parsedValue.authenticatedSafe = new _AuthenticatedSafe2.default({ schema: asn1.result });
						//endregion

						//region Check integrity
						if (parameters.checkIntegrity) {
							var _ret3 = function () {
								//region Check that "MacData" exists
								if ("macData" in _this2 == false) return {
										v: Promise.reject("Absent \"macData\" value, can not check PKCS# data integrity")
									};
								//endregion

								//region Initial variables
								var hashAlgorithm = (0, _common.getAlgorithmByOID)(_this2.macData.mac.digestAlgorithm.algorithmId);
								if ("name" in hashAlgorithm === false) return {
										v: Promise.reject("Unsupported digest algorithm: " + _this2.macData.mac.digestAlgorithm.algorithmId)
									};

								var length = void 0;

								//region Choose correct length for HMAC key
								switch (hashAlgorithm.name.toLowerCase()) {
									case "sha-1":
										length = 160;
										break;
									case "sha-256":
										length = 256;
										break;
									case "sha-384":
										length = 384;
										break;
									case "sha-512":
										length = 512;
										break;
									default:
										return {
											v: Promise.reject("Incorrect \"hashAlgorithm\": " + hashAlgorithm.name)
										};
								}
								//endregion

								var hmacAlgorithm = {
									name: "HMAC",
									length: length,
									hash: {
										name: hashAlgorithm.name
									}
								};
								//endregion

								//region Generate HMAC key using PBKDF2
								//region Derive PBKDF2 key from "password" buffer
								sequence = sequence.then(function () {
									var passwordView = new Uint8Array(parameters.password);

									return crypto.importKey("raw", passwordView, "PBKDF2", true, ['deriveKey']);
								}, function (error) {
									return Promise.reject(error);
								});
								//endregion

								//region Derive key for HMAC
								sequence = sequence.then(function (result) {
									return crypto.deriveKey({
										name: "PBKDF2",
										hash: {
											name: hashAlgorithm.name
										},
										salt: new Uint8Array(_this2.macData.macSalt.valueBlock.valueHex),
										iterations: _this2.macData.iterations
									}, result, hmacAlgorithm, true, ['verify']);
								}, function (error) {
									return Promise.reject(error);
								});
								//endregion
								//endregion

								//region Verify HMAC signature
								sequence = sequence.then(function (result) {
									var data = _this2.authSafe.content.toBER(false);
									var view = new Uint8Array(data);

									return crypto.verify(hmacAlgorithm, result, new Uint8Array(_this2.macData.mac.digest.valueBlock.valueHex), view);
								}, function (error) {
									return Promise.reject(error);
								});

								sequence = sequence.then(function (result) {
									if (result == false) return Promise.reject("Integrity for the PKCS#12 data is broken!");
								}, function (error) {
									return Promise.reject(error);
								});
								//endregion
							}();

							if ((typeof _ret3 === "undefined" ? "undefined" : _typeof(_ret3)) === "object") return _ret3.v;
						}
						//endregion
					}
					break;
				//endregion
				//region signedData
				case "1.2.840.113549.1.7.2":
					{
						var _ret4 = function () {
							//region Integrity based on signature using public key
							_this2.parsedValue.integrityMode = 1;
							//endregion

							//region Parse CMS Signed Data
							var cmsSigned = new _SignedData2.default({ schema: _this2.authSafe.content });
							//endregion

							//region Check that we do have OCTETSTRING as "content"
							if ("eContent" in cmsSigned.encapContentInfo == false) return {
									v: Promise.reject("Absent of attached data in \"cmsSigned.encapContentInfo\"")
								};

							if (cmsSigned.encapContentInfo.eContent instanceof asn1js.OctetString == false) return {
									v: Promise.reject("Wrong type of \"cmsSigned.encapContentInfo.eContent\"")
								};
							//endregion

							//region Create correct data block for verification
							var data = new ArrayBuffer(0);

							if (cmsSigned.encapContentInfo.eContent.idBlock.isConstructed == false) data = cmsSigned.encapContentInfo.eContent.valueBlock.valueHex;else {
								for (var i = 0; i < cmsSigned.encapContentInfo.eContent.valueBlock.value.length; i++) {
									data = (0, _pvutils.utilConcatBuf)(data, cmsSigned.encapContentInfo.eContent.valueBlock.value[i].valueBlock.valueHex);
								}
							}
							//endregion

							//region Parse internal ASN.1 data
							var asn1 = asn1js.fromBER(data);
							if (asn1.offset == -1) return {
									v: Promise.reject("Error during parsing of ASN.1 data inside \"this.authSafe.content\"")
								};
							//endregion

							//region Set "authenticatedSafe" value
							_this2.parsedValue.authenticatedSafe = new _AuthenticatedSafe2.default({ schema: asn1.result });
							//endregion

							//region Check integrity
							sequence = sequence.then(function () {
								return cmsSigned.verify({ signer: 0, checkChain: false });
							}).then(function (result) {
								if (result === false) return Promise.reject("Integrity for the PKCS#12 data is broken!");
							}, function (error) {
								return Promise.reject("Error during integrity verification: " + error);
							});
							//endregion
						}();

						if ((typeof _ret4 === "undefined" ? "undefined" : _typeof(_ret4)) === "object") return _ret4.v;
					}
					break;
				//endregion  
				//region default
				default:
					return Promise.reject("Incorrect value for \"this.authSafe.contentType\": " + this.authSafe.contentType);
				//endregion
			}
			//endregion

			//region Return result of the function
			return sequence.then(function () {
				return _this2;
			}, function (error) {
				return Promise.reject("Error during parsing: " + error);
			});
			//endregion 
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 3;
				case "authSafe":
					return new _ContentInfo2.default();
				case "macData":
					return new _MacData2.default();
				case "parsedValue":
					return {};
				default:
					throw new Error("Invalid member name for PFX class: " + memberName);
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
					return memberValue === PFX.defaultValues(memberName);
				case "authSafe":
					return _ContentInfo2.default.compareWithDefault("contentType", memberValue.contentType) && _ContentInfo2.default.compareWithDefault("content", memberValue.content);
				case "macData":
					return _MacData2.default.compareWithDefault("mac", memberValue.mac) && _MacData2.default.compareWithDefault("macSalt", memberValue.macSalt) && _MacData2.default.compareWithDefault("iterations", memberValue.iterations);
				case "parsedValue":
					return memberValue instanceof Object && Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for PFX class: " + memberName);
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

			//PFX ::= SEQUENCE {
			//    version		INTEGER {v3(3)}(v3,...),
			//    authSafe	ContentInfo,
			//    macData    	MacData OPTIONAL
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [authSafe]
    * @property {string} [macData]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "version" }), _ContentInfo2.default.schema(names.authSafe || {
					names: {
						blockName: "authSafe"
					}
				}), _MacData2.default.schema(names.macData || {
					names: {
						blockName: "macData",
						optional: true
					}
				})]
			});
		}
	}]);

	return PFX;
}();
//**************************************************************************************


exports.default = PFX;
//# sourceMappingURL=PFX.js.map