"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _ResponseData = require("./ResponseData");

var _ResponseData2 = _interopRequireDefault(_ResponseData);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

var _CertID = require("./CertID");

var _CertID2 = _interopRequireDefault(_CertID);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

var _CertificateChainValidationEngine = require("./CertificateChainValidationEngine");

var _CertificateChainValidationEngine2 = _interopRequireDefault(_CertificateChainValidationEngine);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var BasicOCSPResponse = function () {
	//**********************************************************************************
	/**
  * Constructor for BasicOCSPResponse class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function BasicOCSPResponse() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, BasicOCSPResponse);

		//region Internal properties of the object
		/**
   * @type {ResponseData}
   * @description tbsResponseData
   */
		this.tbsResponseData = (0, _pvutils.getParametersValue)(parameters, "tbsResponseData", BasicOCSPResponse.defaultValues("tbsResponseData"));
		/**
   * @type {AlgorithmIdentifier}
   * @description signatureAlgorithm
   */
		this.signatureAlgorithm = (0, _pvutils.getParametersValue)(parameters, "signatureAlgorithm", BasicOCSPResponse.defaultValues("signatureAlgorithm"));
		/**
   * @type {BitString}
   * @description signature
   */
		this.signature = (0, _pvutils.getParametersValue)(parameters, "signature", BasicOCSPResponse.defaultValues("signature"));

		if ("certs" in parameters)
			/**
    * @type {Array.<Certificate>}
    * @description certs
    */
			this.certs = (0, _pvutils.getParametersValue)(parameters, "certs", BasicOCSPResponse.defaultValues("certs"));
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


	_createClass(BasicOCSPResponse, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, BasicOCSPResponse.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OCSP_BASIC_RESPONSE");
			//endregion

			//region Get internal properties from parsed schema
			this.tbsResponseData = new _ResponseData2.default({ schema: asn1.result["BasicOCSPResponse.tbsResponseData"] });
			this.signatureAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result["BasicOCSPResponse.signatureAlgorithm"] });
			this.signature = asn1.result["BasicOCSPResponse.signature"];

			if ("BasicOCSPResponse.certs" in asn1.result) this.certs = Array.from(asn1.result["BasicOCSPResponse.certs"], function (element) {
				return new _Certificate2.default({ schema: element });
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

			outputArray.push(this.tbsResponseData.toSchema());
			outputArray.push(this.signatureAlgorithm.toSchema());
			outputArray.push(this.signature);

			//region Create array of certificates
			if ("certs" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.certs, function (element) {
							return element.toSchema();
						})
					})]
				}));
			}
			//endregion
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
				tbsResponseData: this.tbsResponseData.toJSON(),
				signatureAlgorithm: this.signatureAlgorithm.toJSON(),
				signature: this.signature.toJSON()
			};

			if ("certs" in this) _object.certs = Array.from(this.certs, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************
		/**
   * Get OCSP response status for specific certificate
   * @param {Certificate} certificate Certificate to be checked
   * @param {Certificate} issuerCertificate Certificate of issuer for certificate to be checked
   * @returns {Promise}
   */

	}, {
		key: "getCertificateStatus",
		value: function getCertificateStatus(certificate, issuerCertificate) {
			var _this = this;

			//region Initial variables
			var sequence = Promise.resolve();

			var result = {
				isForCertificate: false,
				status: 2 // 0 = good, 1 = revoked, 2 = unknown
			};

			var hashesObject = {};

			var certIDs = [];
			var certIDPromises = [];
			//endregion

			//region Create all "certIDs" for input certificates
			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = this.tbsResponseData[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var response = _step.value;

					var hashAlgorithm = (0, _common.getAlgorithmByOID)(response.certID.hashAlgorithm.algorithmId);
					if ("name" in hashAlgorithm === false) return Promise.reject("Wrong CertID hashing algorithm: " + response.certID.hashAlgorithm.algorithmId);

					if (hashAlgorithm.name in hashesObject === false) {
						hashesObject[hashAlgorithm.name] = 1;

						var certID = new _CertID2.default();

						certIDs.push(certID);
						certIDPromises.push(certID.createForCertificate(certificate, {
							hashAlgorithm: hashAlgorithm.name,
							issuerCertificate: issuerCertificate
						}));
					}
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

			sequence = sequence.then(function () {
				return Promise.all(certIDPromises);
			});
			//endregion

			//region Compare all response's "certIDs" with identifiers for input certificate
			sequence = sequence.then(function () {
				var _iteratorNormalCompletion2 = true;
				var _didIteratorError2 = false;
				var _iteratorError2 = undefined;

				try {
					for (var _iterator2 = _this.tbsResponseData.responses[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
						var response = _step2.value;
						var _iteratorNormalCompletion3 = true;
						var _didIteratorError3 = false;
						var _iteratorError3 = undefined;

						try {
							for (var _iterator3 = certIDs[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
								var id = _step3.value;

								if (response.certID.isEqual(id)) {
									result.isForCertificate = true;

									if (response.certStatus instanceof asn1js.Primitive) {
										switch (response.certStatus.idBlock.tagNumber) {
											case 0:
												// good
												result.status = 0;
												break;
											case 2:
												// unknown
												result.status = 2;
												break;
											default:
										}
									} else {
										if (response.certStatus instanceof asn1js.Constructed) {
											if (response.certStatus.idBlock.tagNumber === 1) result.status = 1; // revoked
										}
									}

									return result;
								}
							}
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

				return result;
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************
		/**
   * Make signature for current OCSP Basic Response
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
			this.tbsResponseData.tbs = this.tbsResponseData.toSchema(true).toBER(false);
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Signing TBS data on provided private key
			return crypto.sign(defParams.algorithm, privateKey, new Uint8Array(this.tbsResponseData.tbs)).then(function (result) {
				//region Special case for ECDSA algorithm
				if (defParams.algorithm.name === "ECDSA") result = (0, _common.createCMSECDSASignature)(result);
				//endregion

				_this2.signature = new asn1js.BitString({ valueHex: result });
			}, function (error) {
				return Promise.reject("Signing error: " + error);
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Verify existing OCSP Basic Response
   * @param {Object} parameters Additional parameters
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this3 = this;

			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//region Check amount of certificates
			if ("certs" in this === false) return Promise.reject("No certificates attached to the BasicOCSPResponce");
			//endregion

			//region Global variables (used in "promises")
			var signerCert = null;

			var tbsView = new Uint8Array(this.tbsResponseData.tbs);

			var certIndex = -1;

			var sequence = Promise.resolve();

			var shaAlgorithm = "";

			var trustedCerts = [];
			//endregion

			//region Get input values
			if ("trustedCerts" in parameters) trustedCerts = parameters.trustedCerts;
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Find a correct hashing algorithm
			shaAlgorithm = (0, _common.getHashAlgorithm)(this.signatureAlgorithm);
			if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
			//endregion

			//region Find correct value for "responderID"
			var responderType = 0;
			var responderId = {};

			if (this.tbsResponseData.responderID instanceof _RelativeDistinguishedNames2.default) // [1] Name
				{
					responderType = 0;
					responderId = this.tbsResponseData.responderID;
				} else {
				if (this.tbsResponseData.responderID instanceof asn1js.OctetString) // [2] KeyHash
					{
						responderType = 1;
						responderId = this.tbsResponseData.responderID;
					} else return Promise.reject("Wrong value for responderID");
			}
			//endregion

			//region Compare responderID with all certificates one-by-one
			if (responderType === 0) // By Name
				{
					sequence = sequence.then(function () {
						var _iteratorNormalCompletion4 = true;
						var _didIteratorError4 = false;
						var _iteratorError4 = undefined;

						try {
							for (var _iterator4 = _this3.certs.entries()[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
								var _step4$value = _slicedToArray(_step4.value, 2);

								var index = _step4$value[0];
								var certificate = _step4$value[1];

								if (certificate.subject.isEqual(responderId)) {
									certIndex = index;
									break;
								}
							}
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
					});
				} else // By KeyHash
				{
					sequence = sequence.then(function () {
						return Promise.all(Array.from(_this3.certs, function (element) {
							return crypto.digest({ name: "sha-1" }, new Uint8Array(element.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
						})).then(function (results) {
							var _iteratorNormalCompletion5 = true;
							var _didIteratorError5 = false;
							var _iteratorError5 = undefined;

							try {
								for (var _iterator5 = _this3.certs.entries()[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
									var _step5$value = _slicedToArray(_step5.value, 2);

									var index = _step5$value[0];
									var certificate = _step5$value[1];

									if ((0, _pvutils.isEqualBuffer)(results[index], responderId.valueBlock.valueHex)) {
										certIndex = index;
										break;
									}
								}
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
						});
					});
				}
			//endregion

			//region Make additional verification for signer's certificate
			/**
    * Check CA flag for the certificate
    * @param {Certificate} cert Certificate to find CA flag for
    * @returns {*}
    */
			function checkCA(cert) {
				//region Do not include signer's certificate
				if (cert.issuer.isEqual(signerCert.issuer) === true && cert.serialNumber.isEqual(signerCert.serialNumber) === true) return null;
				//endregion

				var isCA = false;

				var _iteratorNormalCompletion6 = true;
				var _didIteratorError6 = false;
				var _iteratorError6 = undefined;

				try {
					for (var _iterator6 = cert.extensions[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
						var extension = _step6.value;

						if (extension.extnID === "2.5.29.19") // BasicConstraints
							{
								if ("cA" in extension.parsedValue) {
									if (extension.parsedValue.cA === true) isCA = true;
								}
							}
					}
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

				if (isCA) return cert;

				return null;
			}

			sequence = sequence.then(function () {
				if (certIndex === -1) return Promise.reject("Correct certificate was not found in OCSP response");

				signerCert = _this3.certs[certIndex];

				return Promise.all(Array.from(_this3.certs, function (element) {
					return checkCA(element);
				})).then(function (promiseResults) {
					var additionalCerts = [];
					additionalCerts.push(signerCert);

					var _iteratorNormalCompletion7 = true;
					var _didIteratorError7 = false;
					var _iteratorError7 = undefined;

					try {
						for (var _iterator7 = promiseResults[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
							var promiseResult = _step7.value;

							if (promiseResult !== null) additionalCerts.push(promiseResult);
						}
					} catch (err) {
						_didIteratorError7 = true;
						_iteratorError7 = err;
					} finally {
						try {
							if (!_iteratorNormalCompletion7 && _iterator7.return) {
								_iterator7.return();
							}
						} finally {
							if (_didIteratorError7) {
								throw _iteratorError7;
							}
						}
					}

					var certChain = new _CertificateChainValidationEngine2.default({
						certs: additionalCerts,
						trustedCerts: trustedCerts
					});

					return certChain.verify().then(function (verificationResult) {
						if (verificationResult.result === true) return Promise.resolve();

						return Promise.reject("Validation of signer's certificate failed");
					}, function (error) {
						return Promise.reject("Validation of signer's certificate failed with error: " + (error instanceof Object ? error.resultMessage : error));
					});
				}, function (promiseError) {
					return Promise.reject("Error during checking certificates for CA flag: " + promiseError);
				});
			});
			//endregion

			//region Import public key from responder certificate
			sequence = sequence.then(function () {
				//region Get information about public key algorithm and default parameters for import
				var algorithmId = void 0;
				if (_this3.certs[certIndex].signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = _this3.certs[certIndex].signatureAlgorithm.algorithmId;else algorithmId = _this3.certs[certIndex].subjectPublicKeyInfo.algorithm.algorithmId;

				var algorithmObject = (0, _common.getAlgorithmByOID)(algorithmId);
				if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + algorithmId);

				var algorithmName = algorithmObject.name;

				var algorithm = (0, _common.getAlgorithmParameters)(algorithmName, "importkey");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;

				//region Special case for ECDSA
				if (algorithmName === "ECDSA") {
					//region Get information about named curve
					if (_this3.certs[certIndex].subjectPublicKeyInfo.algorithm.algorithmParams instanceof asn1js.ObjectIdentifier === false) return Promise.reject("Incorrect type for ECDSA public key parameters");

					var curveObject = (0, _common.getAlgorithmByOID)(_this3.certs[certIndex].subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
					if ("name" in curveObject === false) return Promise.reject("Unsupported named curve algorithm: " + _this3.certs[certIndex].subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
					//endregion

					algorithm.algorithm.namedCurve = curveObject.name;
				}
				//endregion
				//endregion

				var publicKeyInfoSchema = _this3.certs[certIndex].subjectPublicKeyInfo.toSchema();
				var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
				var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

				return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
			});
			//endregion

			//region Verifying TBS part of BasicOCSPResponce
			sequence = sequence.then(function (publicKey) {
				//region Get default algorithm parameters for verification
				var algorithm = (0, _common.getAlgorithmParameters)(publicKey.algorithm.name, "verify");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion

				//region Special case for ECDSA signatures
				var signatureValue = _this3.signature.valueBlock.valueHex;

				if (publicKey.algorithm.name === "ECDSA") {
					var asn1 = asn1js.fromBER(signatureValue);
					signatureValue = (0, _common.createECDSASignatureFromCMS)(asn1.result);
				}
				//endregion

				//region Special case for RSA-PSS
				if (publicKey.algorithm.name === "RSA-PSS") {
					var pssParameters = void 0;

					try {
						pssParameters = new _RSASSAPSSParams2.default({ schema: _this3.signatureAlgorithm.algorithmParams });
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

				return crypto.verify(algorithm.algorithm, publicKey, new Uint8Array(signatureValue), tbsView);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "tbsResponseData":
					return new _ResponseData2.default();
				case "signatureAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signature":
					return new asn1js.BitString();
				case "certs":
					return [];
				default:
					throw new Error("Invalid member name for BasicOCSPResponse class: " + memberName);
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
				case "type":
					{
						var comparisonResult = _ResponseData2.default.compareWithDefault("tbs", memberValue.tbs) && _ResponseData2.default.compareWithDefault("responderID", memberValue.responderID) && _ResponseData2.default.compareWithDefault("producedAt", memberValue.producedAt) && _ResponseData2.default.compareWithDefault("responses", memberValue.responses);

						if ("responseExtensions" in memberValue) comparisonResult = comparisonResult && _ResponseData2.default.compareWithDefault("responseExtensions", memberValue.responseExtensions);

						return comparisonResult;
					}
				case "signatureAlgorithm":
					return memberValue.algorithmId === "" && "algorithmParams" in memberValue === false;
				case "signature":
					return memberValue.isEqual(BasicOCSPResponse.defaultValues(memberName));
				case "certs":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for BasicOCSPResponse class: " + memberName);
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

			//BasicOCSPResponse       ::= SEQUENCE {
			//    tbsResponseData      ResponseData,
			//    signatureAlgorithm   AlgorithmIdentifier,
			//    signature            BIT STRING,
			//    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [tbsResponseData]
    * @property {string} [signatureAlgorithm]
    * @property {string} [signature]
    * @property {string} [certs]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "BasicOCSPResponse",
				value: [_ResponseData2.default.schema(names.tbsResponseData || {
					names: {
						blockName: "BasicOCSPResponse.tbsResponseData"
					}
				}), _AlgorithmIdentifier2.default.schema(names.signatureAlgorithm || {
					names: {
						blockName: "BasicOCSPResponse.signatureAlgorithm"
					}
				}), new asn1js.BitString({ name: names.signature || "BasicOCSPResponse.signature" }), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Sequence({
						value: [new asn1js.Repeated({
							name: "BasicOCSPResponse.certs",
							value: _Certificate2.default.schema(names.certs || {})
						})]
					})]
				})]
			});
		}
	}]);

	return BasicOCSPResponse;
}();
//**************************************************************************************


exports.default = BasicOCSPResponse;
//# sourceMappingURL=BasicOCSPResponse.js.map