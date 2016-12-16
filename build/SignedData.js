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

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _EncapsulatedContentInfo = require("./EncapsulatedContentInfo");

var _EncapsulatedContentInfo2 = _interopRequireDefault(_EncapsulatedContentInfo);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

var _OtherCertificateFormat = require("./OtherCertificateFormat");

var _OtherCertificateFormat2 = _interopRequireDefault(_OtherCertificateFormat);

var _CertificateRevocationList = require("./CertificateRevocationList");

var _CertificateRevocationList2 = _interopRequireDefault(_CertificateRevocationList);

var _OtherRevocationInfoFormat = require("./OtherRevocationInfoFormat");

var _OtherRevocationInfoFormat2 = _interopRequireDefault(_OtherRevocationInfoFormat);

var _SignerInfo = require("./SignerInfo");

var _SignerInfo2 = _interopRequireDefault(_SignerInfo);

var _CertificateSet = require("./CertificateSet");

var _CertificateSet2 = _interopRequireDefault(_CertificateSet);

var _RevocationInfoChoices = require("./RevocationInfoChoices");

var _RevocationInfoChoices2 = _interopRequireDefault(_RevocationInfoChoices);

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

var _TSTInfo = require("./TSTInfo");

var _TSTInfo2 = _interopRequireDefault(_TSTInfo);

var _CertificateChainValidationEngine = require("./CertificateChainValidationEngine");

var _CertificateChainValidationEngine2 = _interopRequireDefault(_CertificateChainValidationEngine);

var _BasicOCSPResponse = require("./BasicOCSPResponse");

var _BasicOCSPResponse2 = _interopRequireDefault(_BasicOCSPResponse);

var _RSASSAPSSParams = require("./RSASSAPSSParams");

var _RSASSAPSSParams2 = _interopRequireDefault(_RSASSAPSSParams);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var SignedData = function () {
	/**
  * Constructor for Attribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function SignedData() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, SignedData);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", SignedData.defaultValues("version"));
		/**
   * @type {Array.<AlgorithmIdentifier>}
   * @description digestAlgorithms
   */
		this.digestAlgorithms = (0, _pvutils.getParametersValue)(parameters, "digestAlgorithms", SignedData.defaultValues("digestAlgorithms"));
		/**
   * @type {EncapsulatedContentInfo}
   * @description encapContentInfo
   */
		this.encapContentInfo = (0, _pvutils.getParametersValue)(parameters, "encapContentInfo", SignedData.defaultValues("encapContentInfo"));

		if ("certificates" in parameters)
			/**
    * @type {Array.<Certificate|OtherCertificateFormat>}
    * @description certificates
    */
			this.certificates = (0, _pvutils.getParametersValue)(parameters, "certificates", SignedData.defaultValues("certificates"));

		if ("crls" in parameters)
			/**
    * @type {Array.<CertificateRevocationList|OtherRevocationInfoFormat>}
    * @description crls
    */
			this.crls = (0, _pvutils.getParametersValue)(parameters, "crls", SignedData.defaultValues("crls"));

		/**
   * @type {Array.<SignerInfo>}
   * @description signerInfos
   */
		this.signerInfos = (0, _pvutils.getParametersValue)(parameters, "signerInfos", SignedData.defaultValues("signerInfos"));
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


	_createClass(SignedData, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, SignedData.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_SIGNED_DATA");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result["SignedData.version"].valueBlock.valueDec;
			this.digestAlgorithms = Array.from(asn1.result["SignedData.digestAlgorithms"], function (algorithm) {
				return new _AlgorithmIdentifier2.default({ schema: algorithm });
			});
			this.encapContentInfo = new _EncapsulatedContentInfo2.default({ schema: asn1.result["SignedData.encapContentInfo"] });

			if ("SignedData.certificates" in asn1.result) {
				this.certificates = Array.from(asn1.result["SignedData.certificates"], function (certificate) {
					if (certificate.idBlock.tagClass === 1) return new _Certificate2.default({ schema: certificate });

					if (certificate.idBlock.tagClass === 3 && certificate.idBlock.tagNumber === 3) {
						//region Create SEQUENCE from [3]
						certificate.idBlock.tagClass = 1; // UNIVERSAL
						certificate.idBlock.tagNumber = 16; // SEQUENCE
						//endregion

						return new _OtherCertificateFormat2.default({ schema: certificate });
					}
					//else // For now we would ignore "AttributeCertificateV1" and "AttributeCertificateV1"
				});
			}

			if ("SignedData.crls" in asn1.result) {
				this.crls = Array.from(asn1.result["SignedData.crls"], function (crl) {
					if (crl.idBlock.tagClass === 1) return new _CertificateRevocationList2.default({ schema: crl });

					//region Create SEQUENCE from [1]
					crl.idBlock.tagClass = 1; // UNIVERSAL
					crl.idBlock.tagNumber = 16; // SEQUENCE
					//endregion

					return new _OtherRevocationInfoFormat2.default({ schema: crl });
				});
			}

			this.signerInfos = Array.from(asn1.result["SignedData.signerInfos"], function (signerInfoSchema) {
				return new _SignerInfo2.default({ schema: signerInfoSchema });
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

			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(new asn1js.Integer({ value: this.version }));

			//region Create array of digest algorithms
			outputArray.push(new asn1js.Set({
				value: Array.from(this.digestAlgorithms, function (algorithm) {
					return algorithm.toSchema(encodeFlag);
				})
			}));
			//endregion

			outputArray.push(this.encapContentInfo.toSchema());

			if ("certificates" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: Array.from(this.certificates, function (certificate) {
						if (certificate instanceof _OtherCertificateFormat2.default) {
							var certificateSchema = certificate.toSchema(encodeFlag);

							certificateSchema.idBlock.tagClass = 3;
							certificateSchema.idBlock.tagNumber = 3;

							return certificateSchema;
						}

						return certificate.toSchema(encodeFlag);
					})
				}));
			}

			if ("crls" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: Array.from(this.crls, function (crl) {
						if (crl instanceof _OtherRevocationInfoFormat2.default) {
							var crlSchema = crl.toSchema(encodeFlag);

							crlSchema.idBlock.tagClass = 3;
							crlSchema.idBlock.tagNumber = 1;

							return crlSchema;
						}

						return crl.toSchema(encodeFlag);
					})
				}));
			}

			//region Create array of signer infos
			outputArray.push(new asn1js.Set({
				value: Array.from(this.signerInfos, function (signerInfo) {
					return signerInfo.toSchema(encodeFlag);
				})
			}));
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
				version: this.version,
				digestAlgorithms: Array.from(this.digestAlgorithms, function (algorithm) {
					return algorithm.toJSON();
				}),
				encapContentInfo: this.encapContentInfo.toJSON()
			};

			if ("certificates" in this) _object.certificates = Array.from(this.certificates, function (certificate) {
				return certificate.toJSON();
			});

			if ("crls" in this) _object.crls = Array.from(this.crls, function (crl) {
				return crl.toJSON();
			});

			_object.signerInfos = Array.from(this.signerInfos, function (signerInfo) {
				return signerInfo.toJSON();
			});

			return _object;
		}
		//**********************************************************************************
		/**
   * Verify current SignedData value
   * @param signer
   * @param data
   * @param trustedCerts
   * @param checkDate
   * @param checkChain
   * @param includeSignerCertificate
   * @param extendedMode
   * @returns {*}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this = this;

			var _ref = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			var _ref$signer = _ref.signer;
			var signer = _ref$signer === undefined ? -1 : _ref$signer;
			var _ref$data = _ref.data;
			var data = _ref$data === undefined ? new ArrayBuffer(0) : _ref$data;
			var _ref$trustedCerts = _ref.trustedCerts;
			var trustedCerts = _ref$trustedCerts === undefined ? [] : _ref$trustedCerts;
			var _ref$checkDate = _ref.checkDate;
			var checkDate = _ref$checkDate === undefined ? new Date() : _ref$checkDate;
			var _ref$checkChain = _ref.checkChain;
			var checkChain = _ref$checkChain === undefined ? false : _ref$checkChain;
			var _ref$includeSignerCer = _ref.includeSignerCertificate;
			var includeSignerCertificate = _ref$includeSignerCer === undefined ? false : _ref$includeSignerCer;
			var _ref$extendedMode = _ref.extendedMode;
			var extendedMode = _ref$extendedMode === undefined ? false : _ref$extendedMode;

			//region Global variables
			var sequence = Promise.resolve();

			var messageDigestValue = new ArrayBuffer(0);

			var publicKey = void 0;

			var shaAlgorithm = "";

			var signerCertificate = {};
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Get a signer number
			if (signer === -1) {
				if (extendedMode) {
					return Promise.reject({
						date: checkDate,
						code: 1,
						message: "Unable to get signer index from input parameters",
						signatureVerified: null,
						signerCertificate: null,
						signerCertificateVerified: null
					});
				}

				return Promise.reject("Unable to get signer index from input parameters");
			}
			//endregion

			//region Check that certificates field was included in signed data
			if ("certificates" in this === false) {
				if (extendedMode) {
					return Promise.reject({
						date: checkDate,
						code: 2,
						message: "No certificates attached to this signed data",
						signatureVerified: null,
						signerCertificate: null,
						signerCertificateVerified: null
					});
				}

				return Promise.reject("No certificates attached to this signed data");
			}
			//endregion

			//region Find a certificate for specified signer
			if (this.signerInfos[signer].sid instanceof _IssuerAndSerialNumber2.default) {
				sequence = sequence.then(function () {
					var _iteratorNormalCompletion = true;
					var _didIteratorError = false;
					var _iteratorError = undefined;

					try {
						for (var _iterator = _this.certificates[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
							var certificate = _step.value;

							if (certificate instanceof _Certificate2.default === false) continue;

							if (certificate.issuer.isEqual(_this.signerInfos[signer].sid.issuer) && certificate.serialNumber.isEqual(_this.signerInfos[signer].sid.serialNumber)) {
								signerCertificate = certificate;
								return Promise.resolve();
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

					if (extendedMode) {
						return Promise.reject({
							date: checkDate,
							code: 3,
							message: "Unable to find signer certificate",
							signatureVerified: null,
							signerCertificate: null,
							signerCertificateVerified: null
						});
					}

					return Promise.reject("Unable to find signer certificate");
				});
			} else // Find by SubjectKeyIdentifier
				{
					sequence = sequence.then(function () {
						return Promise.all(Array.from(_this.certificates.filter(function (certificate) {
							return certificate instanceof _Certificate2.default;
						}), function (certificate) {
							return crypto.digest({ name: "sha-1" }, new Uint8Array(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
						})).then(function (results) {
							var _iteratorNormalCompletion2 = true;
							var _didIteratorError2 = false;
							var _iteratorError2 = undefined;

							try {
								for (var _iterator2 = _this.certificates.entries()[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
									var _step2$value = _slicedToArray(_step2.value, 2);

									var index = _step2$value[0];
									var certificate = _step2$value[1];

									if (certificate instanceof _Certificate2.default === false) continue;

									if ((0, _pvutils.isEqualBuffer)(results[index], _this.signerInfos[signer].sid.valueBlock.valueHex)) {
										signerCertificate = certificate;
										return Promise.resolve();
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

							if (extendedMode) {
								return Promise.reject({
									date: checkDate,
									code: 3,
									message: "Unable to find signer certificate",
									signatureVerified: null,
									signerCertificate: null,
									signerCertificateVerified: null
								});
							}

							return Promise.reject("Unable to find signer certificate");
						}, function () {
							if (extendedMode) {
								return Promise.reject({
									date: checkDate,
									code: 3,
									message: "Unable to find signer certificate",
									signatureVerified: null,
									signerCertificate: null,
									signerCertificateVerified: null
								});
							}

							return Promise.reject("Unable to find signer certificate");
						});
					});
				}
			//endregion

			//region Verify internal digest in case of "tSTInfo" content type
			sequence = sequence.then(function () {
				if (_this.encapContentInfo.eContentType === "1.2.840.113549.1.9.16.1.4") {
					//region Check "eContent" precense
					if ("eContent" in _this.encapContentInfo === false) return false;
					//endregion

					//region Initialize TST_INFO value
					var asn1 = asn1js.fromBER(_this.encapContentInfo.eContent.valueBlock.valueHex);
					var tstInfo = void 0;

					try {
						tstInfo = new _TSTInfo2.default({ schema: asn1.result });
					} catch (ex) {
						return false;
					}
					//endregion

					//region Check that we do have detached data content
					if (data.byteLength === 0) {
						if (extendedMode) {
							return Promise.reject({
								date: checkDate,
								code: 4,
								message: "Missed detached data input array",
								signatureVerified: null,
								signerCertificate: signerCertificate,
								signerCertificateVerified: null
							});
						}

						return Promise.reject("Missed detached data input array");
					}
					//endregion

					return tstInfo.verify({ data: data });
				}

				return true;
			});
			//endregion

			//region Make additional verification for signer's certificate
			function checkCA(cert) {
				/// <param name="cert" type="in_window.org.pkijs.simpl.CERT">Certificate to find CA flag for</param>

				//region Do not include signer's certificate
				if (cert.issuer.isEqual(signerCertificate.issuer) === true && cert.serialNumber.isEqual(signerCertificate.serialNumber) === true) return null;
				//endregion

				var isCA = false;

				var _iteratorNormalCompletion3 = true;
				var _didIteratorError3 = false;
				var _iteratorError3 = undefined;

				try {
					for (var _iterator3 = cert.extensions[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
						var extension = _step3.value;

						if (extension.extnID === "2.5.29.19") // BasicConstraints
							{
								if ("cA" in extension.parsedValue) {
									if (extension.parsedValue.cA === true) isCA = true;
								}
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

				if (isCA) return cert;

				return null;
			}

			if (checkChain) {
				sequence = sequence.then(function (result) {
					//region Veify result of previous operation
					if (result === false) return false;
					//endregion

					return Promise.all(Array.from(_this.certificates.filter(function (certificate) {
						return certificate instanceof _Certificate2.default;
					}), function (certificate) {
						return checkCA(certificate);
					})).then(function (promiseResults) {
						var _certificateChainEngi;

						var certificateChainEngine = new _CertificateChainValidationEngine2.default({
							checkDate: checkDate,
							certs: Array.from(promiseResults.filter(function (_result) {
								return _result !== null;
							})),
							trustedCerts: trustedCerts
						});

						certificateChainEngine.certs.push(signerCertificate);

						if ("crls" in _this) {
							var _iteratorNormalCompletion4 = true;
							var _didIteratorError4 = false;
							var _iteratorError4 = undefined;

							try {
								for (var _iterator4 = _this.crls[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
									var crl = _step4.value;

									if (crl instanceof _CertificateRevocationList2.default) certificateChainEngine.crls.push(crl);else // Assumed "revocation value" has "OtherRevocationInfoFormat"
										{
											if (crl.otherRevInfoFormat === "1.3.6.1.5.5.7.48.1.1") // Basic OCSP response
												certificateChainEngine.ocsps.push(new _BasicOCSPResponse2.default({ schema: crl.otherRevInfo }));
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
						}

						if ("ocsps" in _this) (_certificateChainEngi = certificateChainEngine.ocsps).push.apply(_certificateChainEngi, _toConsumableArray(_this.ocsps));

						return certificateChainEngine.verify().then(function (verificationResult) {
							if (verificationResult.result === true) return Promise.resolve(true);

							if (extendedMode) {
								return Promise.reject({
									date: checkDate,
									code: 5,
									message: "Validation of signer's certificate failed",
									signatureVerified: null,
									signerCertificate: signerCertificate,
									signerCertificateVerified: false
								});
							}

							return Promise.reject("Validation of signer's certificate failed");
						}, function (error) {
							if (extendedMode) {
								return Promise.reject({
									date: checkDate,
									code: 5,
									message: "Validation of signer's certificate failed with error: " + (error instanceof Object ? error.resultMessage : error),
									signatureVerified: null,
									signerCertificate: signerCertificate,
									signerCertificateVerified: false
								});
							}

							return Promise.reject("Validation of signer's certificate failed with error: " + (error instanceof Object ? error.resultMessage : error));
						});
					}, function (promiseError) {
						if (extendedMode) {
							return Promise.reject({
								date: checkDate,
								code: 6,
								message: "Error during checking certificates for CA flag: " + promiseError,
								signatureVerified: null,
								signerCertificate: signerCertificate,
								signerCertificateVerified: null
							});
						}

						return Promise.reject("Error during checking certificates for CA flag: " + promiseError);
					});
				});
			}
			//endregion

			//region Find signer's hashing algorithm
			sequence = sequence.then(function (result) {
				//region Veify result of previous operation
				if (result === false) return false;
				//endregion

				var signerInfoHashAlgorithm = (0, _common.getAlgorithmByOID)(_this.signerInfos[signer].digestAlgorithm.algorithmId);
				if ("name" in signerInfoHashAlgorithm === false) {
					if (extendedMode) {
						return Promise.reject({
							date: checkDate,
							code: 7,
							message: "Unsupported signature algorithm: " + _this.signerInfos[signer].digestAlgorithm.algorithmId,
							signatureVerified: null,
							signerCertificate: signerCertificate,
							signerCertificateVerified: true
						});
					}

					return Promise.reject("Unsupported signature algorithm: " + _this.signerInfos[signer].digestAlgorithm.algorithmId);
				}

				shaAlgorithm = signerInfoHashAlgorithm.name;

				return true;
			});
			//endregion

			//region Create correct data block for verification
			sequence = sequence.then(function (result) {
				//region Veify result of previous operation
				if (result === false) return false;
				//endregion

				if ("eContent" in _this.encapContentInfo) // Attached data
					{
						if (_this.encapContentInfo.eContent.idBlock.tagClass === 1 && _this.encapContentInfo.eContent.idBlock.tagNumber === 4) {
							if (_this.encapContentInfo.eContent.idBlock.isConstructed === false) data = _this.encapContentInfo.eContent.valueBlock.valueHex;else {
								var _iteratorNormalCompletion5 = true;
								var _didIteratorError5 = false;
								var _iteratorError5 = undefined;

								try {
									for (var _iterator5 = _this.encapContentInfo.eContent.valueBlock.value[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
										var contentValue = _step5.value;

										data = (0, _pvutils.utilConcatBuf)(data, contentValue.valueBlock.valueHex);
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
							}
						} else data = _this.encapContentInfo.eContent.valueBlock.valueHex;
					} else // Detached data
					{
						if (data.byteLength === 0) // Check that "data" already provided by function parameter
							{
								if (extendedMode) {
									return Promise.reject({
										date: checkDate,
										code: 8,
										message: "Missed detached data input array",
										signatureVerified: null,
										signerCertificate: signerCertificate,
										signerCertificateVerified: true
									});
								}

								return Promise.reject("Missed detached data input array");
							}
					}

				if ("signedAttrs" in _this.signerInfos[signer]) {
					//region Check mandatory attributes
					var foundContentType = false;
					var foundMessageDigest = false;

					var _iteratorNormalCompletion6 = true;
					var _didIteratorError6 = false;
					var _iteratorError6 = undefined;

					try {
						for (var _iterator6 = _this.signerInfos[signer].signedAttrs.attributes[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
							var attribute = _step6.value;

							//region Check that "content-type" attribute exists
							if (attribute.type === "1.2.840.113549.1.9.3") foundContentType = true;
							//endregion

							//region Check that "message-digest" attribute exists
							if (attribute.type === "1.2.840.113549.1.9.4") {
								foundMessageDigest = true;
								messageDigestValue = attribute.values[0].valueBlock.valueHex;
							}
							//endregion

							//region Speed-up searching
							if (foundContentType && foundMessageDigest) break;
							//endregion
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

					if (foundContentType === false) {
						if (extendedMode) {
							return Promise.reject({
								date: checkDate,
								code: 9,
								message: "Attribute \"content-type\" is a mandatory attribute for \"signed attributes\"",
								signatureVerified: null,
								signerCertificate: signerCertificate,
								signerCertificateVerified: true
							});
						}

						return Promise.reject("Attribute \"content-type\" is a mandatory attribute for \"signed attributes\"");
					}

					if (foundMessageDigest === false) {
						if (extendedMode) {
							return Promise.reject({
								date: checkDate,
								code: 10,
								message: "Attribute \"message-digest\" is a mandatory attribute for \"signed attributes\"",
								signatureVerified: null,
								signerCertificate: signerCertificate,
								signerCertificateVerified: true
							});
						}

						return Promise.reject("Attribute \"message-digest\" is a mandatory attribute for \"signed attributes\"");
					}
					//endregion
				}

				return true;
			});
			//endregion

			//region Import public key from signer's certificate
			sequence = sequence.then(function (result) {
				//region Veify result of previous operation
				if (result === false) return false;
				//endregion

				//region Get information about public key algorithm and default parameters for import
				var algorithmId = void 0;
				if (signerCertificate.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = signerCertificate.signatureAlgorithm.algorithmId;else algorithmId = signerCertificate.subjectPublicKeyInfo.algorithm.algorithmId;

				var algorithmObject = (0, _common.getAlgorithmByOID)(algorithmId);
				if ("name" in algorithmObject === false) {
					if (extendedMode) {
						return Promise.reject({
							date: checkDate,
							code: 11,
							message: "Unsupported public key algorithm: " + algorithmId,
							signatureVerified: null,
							signerCertificate: signerCertificate,
							signerCertificateVerified: true
						});
					}

					return Promise.reject("Unsupported public key algorithm: " + algorithmId);
				}

				var algorithm = (0, _common.getAlgorithmParameters)(algorithmObject.name, "importkey");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;

				//region Special case for ECDSA
				if (algorithmObject.name === "ECDSA") {
					//region Get information about named curve
					if (signerCertificate.subjectPublicKeyInfo.algorithm.algorithmParams instanceof asn1js.ObjectIdentifier === false) return Promise.reject("Incorrect type for ECDSA public key parameters");

					var curveObject = (0, _common.getAlgorithmByOID)(signerCertificate.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
					if ("name" in curveObject === false) return Promise.reject("Unsupported named curve algorithm: " + signerCertificate.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
					//endregion

					algorithm.algorithm.namedCurve = curveObject.name;
				}
				//endregion
				//endregion

				var publicKeyInfoSchema = signerCertificate.subjectPublicKeyInfo.toSchema();
				var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
				var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

				return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
			});
			//endregion

			//region Verify signer's signature
			sequence = sequence.then(function (result) {
				// #region Veify result of previous operation
				if (typeof result == "boolean") return false;
				// #endregion

				publicKey = result;

				// #region Verify "message-digest" attribute in case of "signedAttrs"
				if ("signedAttrs" in _this.signerInfos[signer]) return crypto.digest(shaAlgorithm, new Uint8Array(data));

				return true;
				// #endregion
			}).then(function (result) {
				if ("signedAttrs" in _this.signerInfos[signer]) {
					if ((0, _pvutils.isEqualBuffer)(result, messageDigestValue)) {
						data = _this.signerInfos[signer].signedAttrs.encodedValue;
						return true;
					}

					return false;
				}

				return true;
			}).then(function (result) {
				//region Check result of previous operation
				if (result === false) return false;
				//endregion

				//region Get default algorithm parameters for verification
				var algorithm = (0, _common.getAlgorithmParameters)(publicKey.algorithm.name, "verify");
				if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
				//endregion

				//region Special case for RSA-PSS
				if (publicKey.algorithm.name === "RSA-PSS") {
					var pssParameters = void 0;

					try {
						pssParameters = new _RSASSAPSSParams2.default({ schema: _this.signerInfos[signer].signatureAlgorithm.algorithmParams });
					} catch (ex) {
						if (extendedMode) {
							return Promise.reject({
								date: checkDate,
								code: 12,
								message: ex,
								signatureVerified: null,
								signerCertificate: signerCertificate,
								signerCertificateVerified: true
							});
						}

						return Promise.reject(ex);
					}

					if ("saltLength" in pssParameters) algorithm.algorithm.saltLength = pssParameters.saltLength;else algorithm.algorithm.saltLength = 20;

					var hashName = "SHA-1";

					if ("hashAlgorithm" in pssParameters) {
						var hashAlgorithm = (0, _common.getAlgorithmByOID)(pssParameters.hashAlgorithm.algorithmId);
						if ("name" in hashAlgorithm === false) {
							if (extendedMode) {
								return Promise.reject({
									date: checkDate,
									code: 13,
									message: "Unrecognized hash algorithm: " + pssParameters.hashAlgorithm.algorithmId,
									signatureVerified: null,
									signerCertificate: signerCertificate,
									signerCertificateVerified: true
								});
							}

							return Promise.reject("Unrecognized hash algorithm: " + pssParameters.hashAlgorithm.algorithmId);
						}

						hashName = hashAlgorithm.name;
					}

					algorithm.algorithm.hash.name = hashName;
				}
				//endregion

				//region Special case for ECDSA signatures
				var signatureValue = _this.signerInfos[signer].signature.valueBlock.valueHex;

				if (publicKey.algorithm.name === "ECDSA") {
					var asn1 = asn1js.fromBER(signatureValue);
					signatureValue = (0, _common.createECDSASignatureFromCMS)(asn1.result);
				}
				//endregion

				return crypto.verify(algorithm.algorithm, publicKey, new Uint8Array(signatureValue), new Uint8Array(data));
			});
			//endregion

			//region Make a final result
			sequence = sequence.then(function (result) {
				if (extendedMode) {
					return {
						date: checkDate,
						code: 14,
						message: "",
						signatureVerified: result,
						signerCertificate: signerCertificate,
						signerCertificateVerified: true
					};
				}

				return result;
			}, function (error) {
				if (extendedMode) {
					if ("code" in error) return Promise.reject(error);

					return Promise.reject({
						date: checkDate,
						code: 15,
						message: "Error during verification: " + error.message,
						signatureVerified: null,
						signerCertificate: signerCertificate,
						signerCertificateVerified: true
					});
				}

				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************
		/**
   * Signing current SignedData
   * @param {key} privateKey Private key for "subjectPublicKeyInfo" structure
   * @param {number} signerIndex Index number (starting from 0) of signer index to make signature for
   * @param {string} [hashAlgorithm] Hashing algorithm. Default SHA-1
   * @param {ArrayBuffer} [data] Detached data
   * @returns {*}
   */

	}, {
		key: "sign",
		value: function sign(privateKey, signerIndex, hashAlgorithm, data) {
			var _this2 = this;

			//region Initial variables
			data = data || new ArrayBuffer(0);
			var hashAlgorithmOID = "";
			//endregion

			//region Get a private key from function parameter
			if (typeof privateKey === "undefined") return Promise.reject("Need to provide a private key for signing");
			//endregion

			//region Get hashing algorithm
			if (typeof hashAlgorithm === "undefined") hashAlgorithm = "SHA-1";

			//region Simple check for supported algorithm
			hashAlgorithmOID = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
			if (hashAlgorithmOID === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);
			//endregion
			//endregion

			//region Append information about hash algorithm
			if (this.digestAlgorithms.filter(function (algorithm) {
				return algorithm.algorithmId === hashAlgorithmOID;
			}).length === 0) {
				this.digestAlgorithms.push(new _AlgorithmIdentifier2.default({
					algorithmId: hashAlgorithmOID,
					algorithmParams: new asn1js.Null()
				}));
			}

			this.signerInfos[signerIndex].digestAlgorithm = new _AlgorithmIdentifier2.default({
				algorithmId: hashAlgorithmOID,
				algorithmParams: new asn1js.Null()
			});
			//endregion

			//region Get a "default parameters" for current algorithm
			var defParams = (0, _common.getAlgorithmParameters)(privateKey.algorithm.name, "sign");
			defParams.algorithm.hash.name = hashAlgorithm;
			//endregion

			//region Fill internal structures base on "privateKey" and "hashAlgorithm"
			switch (privateKey.algorithm.name.toUpperCase()) {
				case "RSASSA-PKCS1-V1_5":
				case "ECDSA":
					this.signerInfos[signerIndex].signatureAlgorithm.algorithmId = (0, _common.getOIDByAlgorithm)(defParams.algorithm);
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
							hashAlgorithmOID = (0, _common.getOIDByAlgorithm)({ name: hashAlgorithm });
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
						this.signerInfos[signerIndex].signatureAlgorithm = new _AlgorithmIdentifier2.default({
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
			if ("signedAttrs" in this.signerInfos[signerIndex]) {
				if (this.signerInfos[signerIndex].signedAttrs.encodedValue.byteLength !== 0) data = this.signerInfos[signerIndex].signedAttrs.encodedValue;else {
					data = this.signerInfos[signerIndex].signedAttrs.toSchema(true).toBER(false);

					//region Change type from "[0]" to "SET" acordingly to standard
					var view = new Uint8Array(data);
					view[0] = 0x31;
					//endregion
				}
			} else {
				if ("eContent" in this.encapContentInfo) // Attached data
					{
						if (this.encapContentInfo.eContent.idBlock.tagClass === 1 && this.encapContentInfo.eContent.idBlock.tagNumber === 4) {
							if (this.encapContentInfo.eContent.idBlock.isConstructed === false) data = this.encapContentInfo.eContent.valueBlock.valueHex;else {
								var _iteratorNormalCompletion7 = true;
								var _didIteratorError7 = false;
								var _iteratorError7 = undefined;

								try {
									for (var _iterator7 = this.encapContentInfo.eContent.valueBlock.value[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
										var content = _step7.value;

										data = (0, _pvutils.utilConcatBuf)(data, content.valueBlock.valueHex);
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
							}
						} else data = this.encapContentInfo.eContent.valueBlock.valueHex;
					} else // Detached data
					{
						if (data.byteLength === 0) // Check that "data" already provided by function parameter
							return Promise.reject("Missed detached data input array");
					}
			}
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Signing TBS data on provided private key
			return crypto.sign(defParams.algorithm, privateKey, new Uint8Array(data)).then(function (result) {
				//region Special case for ECDSA algorithm
				if (defParams.algorithm.name === "ECDSA") result = (0, _common.createCMSECDSASignature)(result);
				//endregion

				_this2.signerInfos[signerIndex].signature = new asn1js.OctetString({ valueHex: result });

				return result;
			}, function (error) {
				return Promise.reject("Signing error: " + error);
			});
			//endregion
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 0;
				case "digestAlgorithms":
					return [];
				case "encapContentInfo":
					return new _EncapsulatedContentInfo2.default();
				case "certificates":
					return [];
				case "crls":
					return [];
				case "signerInfos":
					return [];
				default:
					throw new Error("Invalid member name for SignedData class: " + memberName);
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
					return memberValue === SignedData.defaultValues("version");
				case "encapContentInfo":
					return new _EncapsulatedContentInfo2.default();
				case "digestAlgorithms":
				case "certificates":
				case "crls":
				case "signerInfos":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for SignedData class: " + memberName);
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

			//SignedData ::= SEQUENCE {
			//    version CMSVersion,
			//    digestAlgorithms DigestAlgorithmIdentifiers,
			//    encapContentInfo EncapsulatedContentInfo,
			//    certificates [0] IMPLICIT CertificateSet OPTIONAL,
			//    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
			//    signerInfos SignerInfos }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [optional]
    * @property {string} [digestAlgorithms]
    * @property {string} [encapContentInfo]
    * @property {string} [certificates]
    * @property {string} [crls]
    * @property {string} [signerInfos]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			if ("optional" in names === false) names.optional = false;

			return new asn1js.Sequence({
				name: names.blockName || "SignedData",
				optional: names.optional,
				value: [new asn1js.Integer({ name: names.version || "SignedData.version" }), new asn1js.Set({
					value: [new asn1js.Repeated({
						name: names.digestAlgorithms || "SignedData.digestAlgorithms",
						value: _AlgorithmIdentifier2.default.schema()
					})]
				}), _EncapsulatedContentInfo2.default.schema(names.encapContentInfo || {
					names: {
						blockName: "SignedData.encapContentInfo"
					}
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: _CertificateSet2.default.schema(names.certificates || {
						names: {
							certificates: "SignedData.certificates"
						}
					}).valueBlock.value
				}), // IMPLICIT CertificateSet
				new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: _RevocationInfoChoices2.default.schema(names.crls || {
						names: {
							crls: "SignedData.crls"
						}
					}).valueBlock.value
				}), // IMPLICIT RevocationInfoChoices
				new asn1js.Set({
					value: [new asn1js.Repeated({
						name: names.signerInfos || "SignedData.signerInfos",
						value: _SignerInfo2.default.schema()
					})]
				})]
			});
		}
	}]);

	return SignedData;
}();
//**************************************************************************************


exports.default = SignedData;
//# sourceMappingURL=SignedData.js.map