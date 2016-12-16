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

var _RevokedCertificate = require("./RevokedCertificate");

var _RevokedCertificate2 = _interopRequireDefault(_RevokedCertificate);

var _Extensions = require("./Extensions");

var _Extensions2 = _interopRequireDefault(_Extensions);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

var _PublicKeyInfo = require("./PublicKeyInfo");

var _PublicKeyInfo2 = _interopRequireDefault(_PublicKeyInfo);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************
function tbsCertList() {
	var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

	//TBSCertList  ::=  SEQUENCE  {
	//    version                 Version OPTIONAL,
	//                                 -- if present, MUST be v2
	//    signature               AlgorithmIdentifier,
	//    issuer                  Name,
	//    thisUpdate              Time,
	//    nextUpdate              Time OPTIONAL,
	//    revokedCertificates     SEQUENCE OF SEQUENCE  {
	//        userCertificate         CertificateSerialNumber,
	//        revocationDate          Time,
	//        crlEntryExtensions      Extensions OPTIONAL
	//        -- if present, version MUST be v2
	//    }  OPTIONAL,
	//    crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
	//    -- if present, version MUST be v2
	//}

	/**
  * @type {Object}
  * @property {string} [blockName]
  * @property {string} [tbsCertListVersion]
  * @property {string} [signature]
  * @property {string} [issuer]
  * @property {string} [tbsCertListThisUpdate]
  * @property {string} [tbsCertListNextUpdate]
  * @property {string} [tbsCertListRevokedCertificates]
  * @property {string} [crlExtensions]
  */
	var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

	return new asn1js.Sequence({
		name: names.blockName || "tbsCertList",
		value: [new asn1js.Integer({
			optional: true,
			name: names.tbsCertListVersion || "tbsCertList.version",
			value: 2
		}), // EXPLICIT integer value (v2)
		_AlgorithmIdentifier2.default.schema(names.signature || {
			names: {
				blockName: "tbsCertList.signature"
			}
		}), _RelativeDistinguishedNames2.default.schema(names.issuer || {
			names: {
				blockName: "tbsCertList.issuer"
			}
		}), _Time2.default.schema(names.tbsCertListThisUpdate || {
			names: {
				utcTimeName: "tbsCertList.thisUpdate",
				generalTimeName: "tbsCertList.thisUpdate"
			}
		}), _Time2.default.schema(names.tbsCertListNextUpdate || {
			names: {
				utcTimeName: "tbsCertList.nextUpdate",
				generalTimeName: "tbsCertList.nextUpdate"
			}
		}, true), new asn1js.Sequence({
			optional: true,
			value: [new asn1js.Repeated({
				name: names.tbsCertListRevokedCertificates || "tbsCertList.revokedCertificates",
				value: new asn1js.Sequence({
					value: [new asn1js.Integer(), _Time2.default.schema(), _Extensions2.default.schema({}, true)]
				})
			})]
		}), new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 0 // [0]
			},
			value: [_Extensions2.default.schema(names.crlExtensions || {
				names: {
					blockName: "tbsCertList.extensions"
				}
			})]
		}) // EXPLICIT SEQUENCE value
		]
	});
}
//**************************************************************************************

var CertificateRevocationList = function () {
	//**********************************************************************************
	/**
  * Constructor for Attribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertificateRevocationList() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertificateRevocationList);

		//region Internal properties of the object
		/**
   * @type {ArrayBuffer}
   * @description tbs
   */
		this.tbs = (0, _pvutils.getParametersValue)(parameters, "tbs", CertificateRevocationList.defaultValues("tbs"));
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", CertificateRevocationList.defaultValues("version"));
		/**
   * @type {AlgorithmIdentifier}
   * @description signature
   */
		this.signature = (0, _pvutils.getParametersValue)(parameters, "signature", CertificateRevocationList.defaultValues("signature"));
		/**
   * @type {RelativeDistinguishedNames}
   * @description issuer
   */
		this.issuer = (0, _pvutils.getParametersValue)(parameters, "issuer", CertificateRevocationList.defaultValues("issuer"));
		/**
   * @type {Time}
   * @description thisUpdate
   */
		this.thisUpdate = (0, _pvutils.getParametersValue)(parameters, "thisUpdate", CertificateRevocationList.defaultValues("thisUpdate"));

		if ("nextUpdate" in parameters)
			/**
    * @type {Time}
    * @description nextUpdate
    */
			this.nextUpdate = (0, _pvutils.getParametersValue)(parameters, "nextUpdate", CertificateRevocationList.defaultValues("nextUpdate"));

		if ("revokedCertificates" in parameters)
			/**
    * @type {Array.<RevokedCertificate>}
    * @description revokedCertificates
    */
			this.revokedCertificates = (0, _pvutils.getParametersValue)(parameters, "revokedCertificates", CertificateRevocationList.defaultValues("revokedCertificates"));

		if ("crlExtensions" in parameters)
			/**
    * @type {Extensions}
    * @description crlExtensions
    */
			this.crlExtensions = (0, _pvutils.getParametersValue)(parameters, "crlExtensions", CertificateRevocationList.defaultValues("crlExtensions"));

		/**
   * @type {AlgorithmIdentifier}
   * @description signatureAlgorithm
   */
		this.signatureAlgorithm = (0, _pvutils.getParametersValue)(parameters, "signatureAlgorithm", CertificateRevocationList.defaultValues("signatureAlgorithm"));
		/**
   * @type {BitString}
   * @description signatureValue
   */
		this.signatureValue = (0, _pvutils.getParametersValue)(parameters, "signatureValue", CertificateRevocationList.defaultValues("signatureValue"));
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


	_createClass(CertificateRevocationList, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertificateRevocationList.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CRL");
			//endregion

			//region Get internal properties from parsed schema
			this.tbs = asn1.result.tbsCertList.valueBeforeDecode;

			if ("tbsCertList.version" in asn1.result) this.version = asn1.result["tbsCertList.version"].valueBlock.valueDec;
			this.signature = new _AlgorithmIdentifier2.default({ schema: asn1.result["tbsCertList.signature"] });
			this.issuer = new _RelativeDistinguishedNames2.default({ schema: asn1.result["tbsCertList.issuer"] });
			this.thisUpdate = new _Time2.default({ schema: asn1.result["tbsCertList.thisUpdate"] });
			if ("tbsCertList.nextUpdate" in asn1.result) this.nextUpdate = new _Time2.default({ schema: asn1.result["tbsCertList.nextUpdate"] });
			if ("tbsCertList.revokedCertificates" in asn1.result) this.revokedCertificates = Array.from(asn1.result["tbsCertList.revokedCertificates"], function (element) {
				return new _RevokedCertificate2.default({ schema: element });
			});
			if ("tbsCertList.extensions" in asn1.result) this.crlExtensions = new _Extensions2.default({ schema: asn1.result["tbsCertList.extensions"] });

			this.signatureAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.signatureAlgorithm });
			this.signatureValue = asn1.result.signatureValue;
			//endregion
		}
		//**********************************************************************************

	}, {
		key: "encodeTBS",
		value: function encodeTBS() {
			//region Create array for output sequence
			var outputArray = [];

			if (this.version !== CertificateRevocationList.defaultValues("version")) outputArray.push(new asn1js.Integer({ value: this.version }));

			outputArray.push(this.signature.toSchema());
			outputArray.push(this.issuer.toSchema());
			outputArray.push(this.thisUpdate.toSchema());

			if ("nextUpdate" in this) outputArray.push(this.nextUpdate.toSchema());

			if ("revokedCertificates" in this) {
				outputArray.push(new asn1js.Sequence({
					value: Array.from(this.revokedCertificates, function (element) {
						return element.toSchema();
					})
				}));
			}

			if ("crlExtensions" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.crlExtensions.toSchema()]
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
					return CertificateRevocationList.schema();

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
				signature: this.signature.toJSON(),
				issuer: this.issuer.toJSON(),
				thisUpdate: this.thisUpdate.toJSON(),
				signatureAlgorithm: this.signatureAlgorithm.toJSON(),
				signatureValue: this.signatureValue.toJSON()
			};

			if (this.version !== CertificateRevocationList.defaultValues("version")) object.version = this.version;

			if ("nextUpdate" in this) object.nextUpdate = this.nextUpdate.toJSON();

			if ("revokedCertificates" in this) object.revokedCertificates = Array.from(this.revokedCertificates, function (element) {
				return element.toJSON();
			});

			if ("crlExtensions" in this) object.crlExtensions = this.crlExtensions.toJSON();

			return object;
		}
		//**********************************************************************************

	}, {
		key: "isCertificateRevoked",
		value: function isCertificateRevoked(certificate) {
			//region Check that issuer of the input certificate is the same with issuer of this CRL
			if (this.issuer.isEqual(certificate.issuer) === false) return false;
			//endregion

			//region Check that there are revoked certificates in this CRL
			if ("revokedCertificates" in this === false) return false;
			//endregion

			//region Search for input certificate in revoked certificates array
			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = this.revokedCertificates[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var revokedCertificate = _step.value;

					if (revokedCertificate.userCertificate.isEqual(certificate.serialNumber)) return true;
				}
				//endregion
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

			return false;
		}
		//**********************************************************************************
		/**
   * Make a signature for existing CRL data
   * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {string} [hashAlgorithm] Hashing algorithm. Default SHA-1
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
		/**
   * Verify existing signature
   * @param {{[issuerCertificate]: Object, [publicKeyInfo]: Object}} parameters
   * @returns {*}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this2 = this;

			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//region Global variables
			var sequence = Promise.resolve();

			var signature = this.signatureValue;
			var tbs = this.tbs;

			var subjectPublicKeyInfo = -1;
			//endregion

			//region Get information about CRL issuer certificate
			if ("issuerCertificate" in parameters) // "issuerCertificate" must be of type "simpl.CERT"
				{
					subjectPublicKeyInfo = parameters.issuerCertificate.subjectPublicKeyInfo;

					// The CRL issuer name and "issuerCertificate" subject name are not equal
					if (this.issuer.isEqual(parameters.issuerCertificate.subject) === false) return Promise.resolve(false);
				}

			//region In case if there is only public key during verification
			if ("publicKeyInfo" in parameters) subjectPublicKeyInfo = parameters.publicKeyInfo; // Must be of type "PublicKeyInfo"
			//endregion

			if (subjectPublicKeyInfo instanceof _PublicKeyInfo2.default === false) return Promise.reject("Issuer's certificate must be provided as an input parameter");
			//endregion

			//region Check the CRL for unknown critical extensions
			if ("crlExtensions" in this) {
				var _iteratorNormalCompletion2 = true;
				var _didIteratorError2 = false;
				var _iteratorError2 = undefined;

				try {
					for (var _iterator2 = this.crlExtensions.extensions[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
						var extension = _step2.value;

						if (extension.critical) {
							// We can not be sure that unknown extension has no value for CRL signature
							if ("parsedValue" in extension === false) return Promise.resolve(false);
						}
					}
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
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Find signer's hashing algorithm
			var shaAlgorithm = (0, _common.getHashAlgorithm)(this.signatureAlgorithm);
			if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
			//endregion

			//region Import public key
			sequence = sequence.then(function () {
				//region Get information about public key algorithm and default parameters for import
				var algorithmObject = (0, _common.getAlgorithmByOID)(_this2.signature.algorithmId);
				if ("name" in algorithmObject === "") return Promise.reject("Unsupported public key algorithm: " + _this2.signature.algorithmId);

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
					return 1;
				case "signature":
					return new _AlgorithmIdentifier2.default();
				case "issuer":
					return new _RelativeDistinguishedNames2.default();
				case "thisUpdate":
					return new _Time2.default();
				case "nextUpdate":
					return new _Time2.default();
				case "revokedCertificates":
					return [];
				case "crlExtensions":
					return new _Extensions2.default();
				case "signatureAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signatureValue":
					return new asn1js.BitString();
				default:
					throw new Error("Invalid member name for CertificateRevocationList class: " + memberName);
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

			//CertificateList  ::=  SEQUENCE  {
			//    tbsCertList          TBSCertList,
			//    signatureAlgorithm   AlgorithmIdentifier,
			//    signatureValue       BIT STRING  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [signatureAlgorithm]
    * @property {string} [signatureValue]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "CertificateList",
				value: [tbsCertList(parameters), _AlgorithmIdentifier2.default.schema(names.signatureAlgorithm || {
					names: {
						blockName: "signatureAlgorithm"
					}
				}), new asn1js.BitString({ name: names.signatureValue || "signatureValue" })]
			});
		}
	}]);

	return CertificateRevocationList;
}();
//**************************************************************************************


exports.default = CertificateRevocationList;
//# sourceMappingURL=CertificateRevocationList.js.map