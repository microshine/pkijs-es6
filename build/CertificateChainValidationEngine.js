"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _pvutils = require("pvutils");

var _common = require("./common");

var _CertificateRevocationList = require("./CertificateRevocationList");

var _CertificateRevocationList2 = _interopRequireDefault(_CertificateRevocationList);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

var _GeneratorsDriver = require("./GeneratorsDriver");

var _GeneratorsDriver2 = _interopRequireDefault(_GeneratorsDriver);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CertificateChainValidationEngine = function () {
	//**********************************************************************************
	/**
  * Constructor for CertificateChainValidationEngine class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertificateChainValidationEngine() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertificateChainValidationEngine);

		//region Internal properties of the object
		/**
   * @type {Array.<Certificate>}
   * @description Array of pre-defined trusted (by user) certificates
   */
		this.trustedCerts = (0, _pvutils.getParametersValue)(parameters, "trustedCerts", CertificateChainValidationEngine.defaultValues("trustedCerts"));
		/**
   * @type {Array.<Certificate>}
   * @description Array with certificate chain. Could be only one end-user certificate in there!
   */
		this.certs = (0, _pvutils.getParametersValue)(parameters, "certs", CertificateChainValidationEngine.defaultValues("certs"));
		/**
   * @type {Array.<CertificateRevocationList>}
   * @description Array of all CRLs for all certificates from certificate chain
   */
		this.crls = (0, _pvutils.getParametersValue)(parameters, "crls", CertificateChainValidationEngine.defaultValues("crls"));
		/**
   * @type {Array}
   * @description Array of all OCSP responses
   */
		this.ocsps = (0, _pvutils.getParametersValue)(parameters, "ocsps", CertificateChainValidationEngine.defaultValues("ocsps"));
		/**
   * @type {Date}
   * @description The date at which the check would be
   */
		this.checkDate = (0, _pvutils.getParametersValue)(parameters, "checkDate", CertificateChainValidationEngine.defaultValues("checkDate"));
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


	_createClass(CertificateChainValidationEngine, [{
		key: "sort",

		//**********************************************************************************
		value: function sort() {
			var _marked = [findIssuer, buildPath, findCRL, findOCSP, checkForCA, basicCheck].map(regeneratorRuntime.mark);

			//region Initial variables
			var localCerts = [];
			var _this = this;
			//endregion

			//region Finding certificate issuer
			function findIssuer(certificate, index) {
				var result, i, verificationResult;
				return regeneratorRuntime.wrap(function findIssuer$(_context) {
					while (1) {
						switch (_context.prev = _context.next) {
							case 0:
								result = [];
								i = 0;

							case 2:
								if (!(i < localCerts.length)) {
									_context.next = 15;
									break;
								}

								_context.prev = 3;
								_context.next = 6;
								return certificate.verify(localCerts[i]);

							case 6:
								verificationResult = _context.sent;

								if (verificationResult) result.push(i);
								_context.next = 12;
								break;

							case 10:
								_context.prev = 10;
								_context.t0 = _context["catch"](3);

							case 12:
								i++;
								_context.next = 2;
								break;

							case 15:
								return _context.abrupt("return", result.length ? result : [-1]);

							case 16:
							case "end":
								return _context.stop();
						}
					}
				}, _marked[0], this, [[3, 10]]);
			}
			//endregion

			//region Building certificate path
			function buildPath(certificate, index) {
				var result, checkUnique, findIssuerResult, buildPathResult, i, copy, _i, _buildPathResult, j, _copy;

				return regeneratorRuntime.wrap(function buildPath$(_context2) {
					while (1) {
						switch (_context2.prev = _context2.next) {
							case 0:
								checkUnique = function checkUnique(array) {
									var unique = true;

									for (var i = 0; i < array.length; i++) {
										for (var j = 0; j < array.length; j++) {
											if (j === i) continue;

											if (array[i] === array[j]) {
												unique = false;
												break;
											}
										}

										if (!unique) break;
									}

									return unique;
								};

								result = [];

								//region Aux function checking array for unique elements

								_context2.next = 4;
								return findIssuer(certificate, index);

							case 4:
								findIssuerResult = _context2.sent;

								if (!(findIssuerResult.length === 1 && findIssuerResult[0] === -1)) {
									_context2.next = 7;
									break;
								}

								throw new Error("Incorrect result");

							case 7:
								if (!(findIssuerResult.length === 1)) {
									_context2.next = 17;
									break;
								}

								if (!(findIssuerResult[0] === index)) {
									_context2.next = 11;
									break;
								}

								result.push(findIssuerResult);
								return _context2.abrupt("return", result);

							case 11:
								_context2.next = 13;
								return buildPath(localCerts[findIssuerResult[0]], findIssuerResult[0]);

							case 13:
								buildPathResult = _context2.sent;


								for (i = 0; i < buildPathResult.length; i++) {
									copy = buildPathResult[i].slice();

									copy.splice(0, 0, findIssuerResult[0]);

									if (checkUnique(copy)) result.push(copy);else result.push(buildPathResult[i]);
								}
								_context2.next = 29;
								break;

							case 17:
								_i = 0;

							case 18:
								if (!(_i < findIssuerResult.length)) {
									_context2.next = 29;
									break;
								}

								if (!(findIssuerResult[_i] === index)) {
									_context2.next = 22;
									break;
								}

								result.push([findIssuerResult[_i]]);
								return _context2.abrupt("continue", 26);

							case 22:
								_context2.next = 24;
								return buildPath(localCerts[findIssuerResult[_i]], findIssuerResult[_i]);

							case 24:
								_buildPathResult = _context2.sent;


								for (j = 0; j < _buildPathResult.length; j++) {
									_copy = _buildPathResult[j].slice();

									_copy.splice(0, 0, findIssuerResult[_i]);

									if (checkUnique(_copy)) result.push(_copy);else result.push(_buildPathResult[j]);
								}

							case 26:
								_i++;
								_context2.next = 18;
								break;

							case 29:
								return _context2.abrupt("return", result);

							case 30:
							case "end":
								return _context2.stop();
						}
					}
				}, _marked[1], this);
			}
			//endregion

			//region Find CRL for specific certificate
			function findCRL(certificate) {
				var issuerCertificates, crls, crlsAndCertificates, i, j, result;
				return regeneratorRuntime.wrap(function findCRL$(_context3) {
					while (1) {
						switch (_context3.prev = _context3.next) {
							case 0:
								//region Initial variables
								issuerCertificates = [];
								crls = [];
								crlsAndCertificates = [];
								//endregion

								//region Find all possible CRL issuers

								issuerCertificates.push.apply(issuerCertificates, _toConsumableArray(localCerts.filter(function (element) {
									return certificate.issuer.isEqual(element.subject);
								})));

								if (!(issuerCertificates.length === 0)) {
									_context3.next = 6;
									break;
								}

								return _context3.abrupt("return", {
									status: 1,
									statusMessage: "No certificate's issuers"
								});

							case 6:
								//endregion

								//region Find all CRLs for crtificate's issuer
								crls.push.apply(crls, _toConsumableArray(_this.crls.filter(function (element) {
									return element.issuer.isEqual(certificate.issuer);
								})));

								if (!(crls.length === 0)) {
									_context3.next = 9;
									break;
								}

								return _context3.abrupt("return", {
									status: 1,
									statusMessage: "No CRLs for specific certificate issuer"
								});

							case 9:
								i = 0;

							case 10:
								if (!(i < crls.length)) {
									_context3.next = 32;
									break;
								}

								if (!(crls[i].nextUpdate.value < _this.checkDate)) {
									_context3.next = 13;
									break;
								}

								return _context3.abrupt("continue", 29);

							case 13:
								j = 0;

							case 14:
								if (!(j < issuerCertificates.length)) {
									_context3.next = 29;
									break;
								}

								_context3.prev = 15;
								_context3.next = 18;
								return crls[i].verify({ issuerCertificate: issuerCertificates[j] });

							case 18:
								result = _context3.sent;

								if (!result) {
									_context3.next = 22;
									break;
								}

								crlsAndCertificates.push({
									crl: crls[i],
									certificate: issuerCertificates[j]
								});

								return _context3.abrupt("break", 29);

							case 22:
								_context3.next = 26;
								break;

							case 24:
								_context3.prev = 24;
								_context3.t0 = _context3["catch"](15);

							case 26:
								j++;
								_context3.next = 14;
								break;

							case 29:
								i++;
								_context3.next = 10;
								break;

							case 32:
								if (!crlsAndCertificates.length) {
									_context3.next = 34;
									break;
								}

								return _context3.abrupt("return", {
									status: 0,
									statusMessage: "",
									result: crlsAndCertificates
								});

							case 34:
								return _context3.abrupt("return", {
									status: 1,
									statusMessage: "No valid CRLs found"
								});

							case 35:
							case "end":
								return _context3.stop();
						}
					}
				}, _marked[2], this, [[15, 24]]);
			}
			//endregion

			//region Find OCSP for specific certificate
			function findOCSP(certificate, issuerCertificate) {
				var hashAlgorithm, i, result;
				return regeneratorRuntime.wrap(function findOCSP$(_context4) {
					while (1) {
						switch (_context4.prev = _context4.next) {
							case 0:
								//region Get hash algorithm from certificate
								hashAlgorithm = (0, _common.getAlgorithmByOID)(certificate.signatureAlgorithm.algorithmId);

								if (!("name" in hashAlgorithm === false)) {
									_context4.next = 3;
									break;
								}

								return _context4.abrupt("return", 1);

							case 3:
								if (!("hash" in hashAlgorithm === false)) {
									_context4.next = 5;
									break;
								}

								return _context4.abrupt("return", 1);

							case 5:
								i = 0;

							case 6:
								if (!(i < _this.ocsps.length)) {
									_context4.next = 17;
									break;
								}

								_context4.next = 9;
								return _this.ocsps[i].getCertificateStatus(certificate, issuerCertificate);

							case 9:
								result = _context4.sent;

								if (!result.isForCertificate) {
									_context4.next = 14;
									break;
								}

								if (!(result.status === 0)) {
									_context4.next = 13;
									break;
								}

								return _context4.abrupt("return", 0);

							case 13:
								return _context4.abrupt("return", 1);

							case 14:
								i++;
								_context4.next = 6;
								break;

							case 17:
								return _context4.abrupt("return", 2);

							case 18:
							case "end":
								return _context4.stop();
						}
					}
				}, _marked[3], this);
			}
			//endregion

			//region Check for certificate to be CA
			function checkForCA(certificate) {
				var needToCheckCRL = arguments.length <= 1 || arguments[1] === undefined ? false : arguments[1];
				var isCA, mustBeCA, keyUsagePresent, cRLSign, j, view;
				return regeneratorRuntime.wrap(function checkForCA$(_context5) {
					while (1) {
						switch (_context5.prev = _context5.next) {
							case 0:
								//region Initial variables
								isCA = false;
								mustBeCA = false;
								keyUsagePresent = false;
								cRLSign = false;
								//endregion

								if (!("extensions" in certificate)) {
									_context5.next = 20;
									break;
								}

								j = 0;

							case 6:
								if (!(j < certificate.extensions.length)) {
									_context5.next = 14;
									break;
								}

								if (!(certificate.extensions[j].critical === true && "parsedValue" in certificate.extensions[j] === false)) {
									_context5.next = 9;
									break;
								}

								return _context5.abrupt("return", {
									result: false,
									resultCode: 6,
									resultMessage: "Unable to parse critical certificate extension: " + certificate.extensions[j].extnID
								});

							case 9:

								if (certificate.extensions[j].extnID === "2.5.29.15") // KeyUsage
									{
										keyUsagePresent = true;

										view = new Uint8Array(certificate.extensions[j].parsedValue.valueBlock.valueHex);


										if ((view[0] & 0x04) === 0x04) // Set flag "keyCertSign"
											mustBeCA = true;

										if ((view[0] & 0x02) === 0x02) // Set flag "cRLSign"
											cRLSign = true;
									}

								if (certificate.extensions[j].extnID === "2.5.29.19") // BasicConstraints
									{
										if ("cA" in certificate.extensions[j].parsedValue) {
											if (certificate.extensions[j].parsedValue.cA === true) isCA = true;
										}
									}

							case 11:
								j++;
								_context5.next = 6;
								break;

							case 14:
								if (!(mustBeCA === true && isCA === false)) {
									_context5.next = 16;
									break;
								}

								return _context5.abrupt("return", {
									result: false,
									resultCode: 3,
									resultMessage: "Unable to build certificate chain - using \"keyCertSign\" flag set without BasicConstaints"
								});

							case 16:
								if (!(keyUsagePresent === true && isCA === true && mustBeCA === false)) {
									_context5.next = 18;
									break;
								}

								return _context5.abrupt("return", {
									result: false,
									resultCode: 4,
									resultMessage: "Unable to build certificate chain - \"keyCertSign\" flag was not set"
								});

							case 18:
								if (!(isCA === true && keyUsagePresent === true && needToCheckCRL && cRLSign === false)) {
									_context5.next = 20;
									break;
								}

								return _context5.abrupt("return", {
									result: false,
									resultCode: 5,
									resultMessage: "Unable to build certificate chain - intermediate certificate must have \"cRLSign\" key usage flag"
								});

							case 20:
								if (!(isCA === false)) {
									_context5.next = 22;
									break;
								}

								return _context5.abrupt("return", {
									result: false,
									resultCode: 7,
									resultMessage: "Unable to build certificate chain - more than one possible end-user certificate"
								});

							case 22:
								return _context5.abrupt("return", {
									result: true,
									resultCode: 0,
									resultMessage: ""
								});

							case 23:
							case "end":
								return _context5.stop();
						}
					}
				}, _marked[4], this);
			}
			//endregion

			//region Basic check for certificate path
			function basicCheck(path, checkDate) {
				var i, _i2, _i3, ocspResult, crlResult, j, isCertificateRevoked, isCertificateCA, _i4, result;

				return regeneratorRuntime.wrap(function basicCheck$(_context6) {
					while (1) {
						switch (_context6.prev = _context6.next) {
							case 0:
								i = 0;

							case 1:
								if (!(i < path.length)) {
									_context6.next = 7;
									break;
								}

								if (!(path[i].notBefore.value > checkDate || path[i].notAfter.value < checkDate)) {
									_context6.next = 4;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 8,
									resultMessage: "Certificate validity period is out of checking date"
								});

							case 4:
								i++;
								_context6.next = 1;
								break;

							case 7:
								if (!(path.length < 2)) {
									_context6.next = 9;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 9,
									resultMessage: "Too short certificate path"
								});

							case 9:
								_i2 = path.length - 2;

							case 10:
								if (!(_i2 >= 0)) {
									_context6.next = 17;
									break;
								}

								if (!(path[_i2].issuer.isEqual(path[_i2].subject) === false)) {
									_context6.next = 14;
									break;
								}

								if (!(path[_i2].issuer.isEqual(path[_i2 + 1].subject) === false)) {
									_context6.next = 14;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 10,
									resultMessage: "Incorrect name chaining"
								});

							case 14:
								_i2--;
								_context6.next = 10;
								break;

							case 17:
								if (!(_this.crls.length !== 0 || _this.ocsps.length !== 0)) {
									_context6.next = 58;
									break;
								}

								_i3 = 0;

							case 19:
								if (!(_i3 < path.length - 2)) {
									_context6.next = 58;
									break;
								}

								//region Initial variables
								ocspResult = void 0;
								crlResult = void 0;
								//endregion

								//region Check OCSPs first

								if (!(_this.ocsps.length !== 0)) {
									_context6.next = 32;
									break;
								}

								_context6.next = 25;
								return findOCSP(path[_i3], path[_i3 + 1]);

							case 25:
								ocspResult = _context6.sent;
								_context6.t0 = ocspResult;
								_context6.next = _context6.t0 === 0 ? 29 : _context6.t0 === 1 ? 30 : _context6.t0 === 2 ? 31 : 32;
								break;

							case 29:
								return _context6.abrupt("continue", 55);

							case 30:
								return _context6.abrupt("return", {
									result: false,
									resultCode: 12,
									resultMessage: "One of certificates was revoked via OCSP response"
								});

							case 31:
								return _context6.abrupt("break", 32);

							case 32:
								if (!(_this.crls.length !== 0)) {
									_context6.next = 53;
									break;
								}

								_context6.next = 35;
								return findCRL(path[_i3]);

							case 35:
								crlResult = _context6.sent;

								if (!crlResult.status) {
									_context6.next = 38;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 11,
									resultMessage: "No revocation values found for one of certificates"
								});

							case 38:
								j = 0;

							case 39:
								if (!(j < crlResult.result.length)) {
									_context6.next = 51;
									break;
								}

								//region Check that the CRL issuer certificate have not been revoked
								isCertificateRevoked = crlResult.result[j].crl.isCertificateRevoked(path[_i3]);

								if (!isCertificateRevoked) {
									_context6.next = 43;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 12,
									resultMessage: "One of certificates had been revoked"
								});

							case 43:
								_context6.next = 45;
								return checkForCA(crlResult.result[j].certificate, true);

							case 45:
								isCertificateCA = _context6.sent;

								if (!(isCertificateCA.result === false)) {
									_context6.next = 48;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 13,
									resultMessage: "CRL issuer certificate is not a CA certificate or does not have crlSign flag"
								});

							case 48:
								j++;
								_context6.next = 39;
								break;

							case 51:
								_context6.next = 55;
								break;

							case 53:
								if (!(ocspResult === 2)) {
									_context6.next = 55;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 11,
									resultMessage: "No revocation values found for one of certificates"
								});

							case 55:
								_i3++;
								_context6.next = 19;
								break;

							case 58:
								_i4 = 1;

							case 59:
								if (!(_i4 < path.length)) {
									_context6.next = 68;
									break;
								}

								_context6.next = 62;
								return checkForCA(path[_i4]);

							case 62:
								result = _context6.sent;

								if (!(result.result === false)) {
									_context6.next = 65;
									break;
								}

								return _context6.abrupt("return", {
									result: false,
									resultCode: 14,
									resultMessage: "One of intermediate certificates is not a CA certificate"
								});

							case 65:
								_i4++;
								_context6.next = 59;
								break;

							case 68:
								return _context6.abrupt("return", {
									result: true
								});

							case 69:
							case "end":
								return _context6.stop();
						}
					}
				}, _marked[5], this);
			}
			//endregion

			return (0, _GeneratorsDriver2.default)(regeneratorRuntime.mark(function generatorFunction() {
				var i, j, result, certificatePath, _i5, found, latestItem, certificate, _j, shortestLength, shortestIndex, _i6, _i7;

				return regeneratorRuntime.wrap(function generatorFunction$(_context7) {
					while (1) {
						switch (_context7.prev = _context7.next) {
							case 0:
								//region Initialize "localCerts" by value of "_this.certs" + "_this.trustedCerts" arrays
								localCerts.push.apply(localCerts, _toConsumableArray(_this.trustedCerts));
								localCerts.push.apply(localCerts, _toConsumableArray(_this.certs));
								//endregion

								//region Check all certificates for been unique
								i = 0;

							case 3:
								if (!(i < localCerts.length)) {
									_context7.next = 18;
									break;
								}

								j = 0;

							case 5:
								if (!(j < localCerts.length)) {
									_context7.next = 15;
									break;
								}

								if (!(i === j)) {
									_context7.next = 8;
									break;
								}

								return _context7.abrupt("continue", 12);

							case 8:
								if (!(0, _pvutils.isEqualBuffer)(localCerts[i].tbs, localCerts[j].tbs)) {
									_context7.next = 12;
									break;
								}

								localCerts.splice(j, 1);
								i = 0;
								return _context7.abrupt("break", 15);

							case 12:
								j++;
								_context7.next = 5;
								break;

							case 15:
								i++;
								_context7.next = 3;
								break;

							case 18:
								//endregion

								//region Initial variables
								result = void 0;
								certificatePath = [localCerts[localCerts.length - 1]]; // The "end entity" certificate must be the least in "certs" array
								//endregion

								//region Build path for "end entity" certificate

								_context7.next = 22;
								return buildPath(localCerts[localCerts.length - 1], localCerts.length - 1);

							case 22:
								result = _context7.sent;

								if (!(result.length === 0)) {
									_context7.next = 25;
									break;
								}

								return _context7.abrupt("return", {
									result: false,
									resultCode: 60,
									resultMessage: "Unable to find certificate path"
								});

							case 25:
								_i5 = 0;

							case 26:
								if (!(_i5 < result.length)) {
									_context7.next = 42;
									break;
								}

								found = false;
								latestItem = result[_i5].length - 1;
								certificate = localCerts[result[_i5][latestItem]];
								_j = 0;

							case 31:
								if (!(_j < _this.trustedCerts.length)) {
									_context7.next = 38;
									break;
								}

								if (!(0, _pvutils.isEqualBuffer)(certificate.tbs, _this.trustedCerts[_j].tbs)) {
									_context7.next = 35;
									break;
								}

								found = true;
								return _context7.abrupt("break", 38);

							case 35:
								_j++;
								_context7.next = 31;
								break;

							case 38:

								if (!found) {
									result.splice(_i5, 1);
									_i5 = 0;
								}

							case 39:
								_i5++;
								_context7.next = 26;
								break;

							case 42:
								if (!(result.length === 0)) {
									_context7.next = 44;
									break;
								}

								throw {
									result: false,
									resultCode: 97,
									resultMessage: "No valid certificate paths found"
								};

							case 44:
								//endregion

								//region Find shortest certificate path (for the moment it is the only criteria)
								shortestLength = result[0].length;
								shortestIndex = 0;


								for (_i6 = 0; _i6 < result.length; _i6++) {
									if (result[_i6].length < shortestLength) {
										shortestLength = result[_i6].length;
										shortestIndex = _i6;
									}
								}
								//endregion

								//region Create certificate path for basic check
								for (_i7 = 0; _i7 < result[shortestIndex].length; _i7++) {
									certificatePath.push(localCerts[result[shortestIndex][_i7]]);
								} //endregion

								//region Perform basic checking for all certificates in the path
								_context7.next = 50;
								return basicCheck(certificatePath, _this.checkDate);

							case 50:
								result = _context7.sent;

								if (!(result.result === false)) {
									_context7.next = 53;
									break;
								}

								throw result;

							case 53:
								return _context7.abrupt("return", certificatePath);

							case 54:
							case "end":
								return _context7.stop();
						}
					}
				}, generatorFunction, this);
			}));
		}
		//**********************************************************************************
		/**
   * Major verification function for certificate chain.
   * @param {{initialPolicySet, initialExplicitPolicy, initialPolicyMappingInhibit, initialInhibitPolicy, initialPermittedSubtreesSet, initialExcludedSubtreesSet, initialRequiredNameForms}} [parameters]
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this2 = this;

			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//region Initial checks
			if (this.certs.length === 0) return Promise.reject("Empty certificate array");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();
			//endregion

			//region Get input variables
			var initialPolicySet = [];
			initialPolicySet.push("2.5.29.32.0"); // "anyPolicy"

			var initialExplicitPolicy = false;
			var initialPolicyMappingInhibit = false;
			var initialInhibitPolicy = false;

			var initialPermittedSubtreesSet = []; // Array of "simpl.x509.GeneralSubtree"
			var initialExcludedSubtreesSet = []; // Array of "simpl.x509.GeneralSubtree"
			var initialRequiredNameForms = []; // Array of "simpl.x509.GeneralSubtree"

			if ("initialPolicySet" in parameters) initialPolicySet = parameters.initialPolicySet;

			if ("initialExplicitPolicy" in parameters) initialExplicitPolicy = parameters.initialExplicitPolicy;

			if ("initialPolicyMappingInhibit" in parameters) initialPolicyMappingInhibit = parameters.initialPolicyMappingInhibit;

			if ("initialInhibitPolicy" in parameters) initialInhibitPolicy = parameters.initialInhibitPolicy;

			if ("initialPermittedSubtreesSet" in parameters) initialPermittedSubtreesSet = parameters.initialPermittedSubtreesSet;

			if ("initialExcludedSubtreesSet" in parameters) initialExcludedSubtreesSet = parameters.initialExcludedSubtreesSet;

			if ("initialRequiredNameForms" in parameters) initialRequiredNameForms = parameters.initialRequiredNameForms;

			var explicitPolicyIndicator = initialExplicitPolicy;
			var policyMappingInhibitIndicator = initialPolicyMappingInhibit;
			var inhibitAnyPolicyIndicator = initialInhibitPolicy;

			var pendingConstraints = new Array(3);
			pendingConstraints[0] = false; // For "explicitPolicyPending"
			pendingConstraints[1] = false; // For "policyMappingInhibitPending"
			pendingConstraints[2] = false; // For "inhibitAnyPolicyPending"

			var explicitPolicyPending = 0;
			var policyMappingInhibitPending = 0;
			var inhibitAnyPolicyPending = 0;

			var permittedSubtrees = initialPermittedSubtreesSet;
			var excludedSubtrees = initialExcludedSubtreesSet;
			var requiredNameForms = initialRequiredNameForms;

			var pathDepth = 1;
			//endregion

			//region Sorting certificates in the chain array
			sequence = this.sort().then(function (sortedCerts) {
				_this2.certs = sortedCerts;
			});
			//endregion

			//region Work with policies
			sequence = sequence.then(function () {
				//region Support variables
				var allPolicies = []; // Array of all policies (string values)
				allPolicies.push("2.5.29.32.0"); // Put "anyPolicy" at first place

				var policiesAndCerts = []; // In fact "array of array" where rows are for each specific policy, column for each certificate and value is "true/false"

				var anyPolicyArray = new Array(_this2.certs.length - 1); // Minus "trusted anchor"
				for (var ii = 0; ii < _this2.certs.length - 1; ii++) {
					anyPolicyArray[ii] = true;
				}policiesAndCerts.push(anyPolicyArray);

				var policyMappings = new Array(_this2.certs.length - 1); // Array of "PolicyMappings" for each certificate
				var certPolicies = new Array(_this2.certs.length - 1); // Array of "CertificatePolicies" for each certificate

				var explicitPolicyStart = explicitPolicyIndicator ? _this2.certs.length - 1 : -1;
				//endregion

				//region Gather all neccessary information from certificate chain
				for (var i = _this2.certs.length - 2; i >= 0; i--, pathDepth++) {
					if ("extensions" in _this2.certs[i]) {
						//region Get information about certificate extensions
						for (var j = 0; j < _this2.certs[i].extensions.length; j++) {
							//region CertificatePolicies
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.32") {
								certPolicies[i] = _this2.certs[i].extensions[j].parsedValue;

								//region Remove entry from "anyPolicies" for the certificate
								for (var s = 0; s < allPolicies.length; s++) {
									if (allPolicies[s] === "2.5.29.32.0") {
										delete policiesAndCerts[s][i];
										break;
									}
								}
								//endregion

								for (var k = 0; k < _this2.certs[i].extensions[j].parsedValue.certificatePolicies.length; k++) {
									var policyIndex = -1;

									//region Try to find extension in "allPolicies" array
									for (var _s = 0; _s < allPolicies.length; _s++) {
										if (_this2.certs[i].extensions[j].parsedValue.certificatePolicies[k].policyIdentifier === allPolicies[_s]) {
											policyIndex = _s;
											break;
										}
									}
									//endregion

									if (policyIndex === -1) {
										allPolicies.push(_this2.certs[i].extensions[j].parsedValue.certificatePolicies[k].policyIdentifier);

										var certArray = new Array(_this2.certs.length - 1);
										certArray[i] = true;

										policiesAndCerts.push(certArray);
									} else policiesAndCerts[policyIndex][i] = true;
								}
							}
							//endregion

							//region PolicyMappings
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.33") {
								if (policyMappingInhibitIndicator) {
									return {
										result: false,
										resultCode: 98,
										resultMessage: "Policy mapping prohibited"
									};
								}

								policyMappings[i] = _this2.certs[i].extensions[j].parsedValue;
							}
							//endregion

							//region PolicyConstraints
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.36") {
								if (explicitPolicyIndicator === false) {
									//region requireExplicitPolicy
									if (_this2.certs[i].extensions[j].parsedValue.requireExplicitPolicy === 0) {
										explicitPolicyIndicator = true;
										explicitPolicyStart = i;
									} else {
										if (pendingConstraints[0] === false) {
											pendingConstraints[0] = true;
											explicitPolicyPending = _this2.certs[i].extensions[j].parsedValue.requireExplicitPolicy;
										} else explicitPolicyPending = explicitPolicyPending > _this2.certs[i].extensions[j].parsedValue.requireExplicitPolicy ? _this2.certs[i].extensions[j].parsedValue.requireExplicitPolicy : explicitPolicyPending;
									}
									//endregion

									//region inhibitPolicyMapping
									if (_this2.certs[i].extensions[j].parsedValue.inhibitPolicyMapping === 0) policyMappingInhibitIndicator = true;else {
										if (pendingConstraints[1] === false) {
											pendingConstraints[1] = true;
											policyMappingInhibitPending = _this2.certs[i].extensions[j].parsedValue.inhibitPolicyMapping + 1;
										} else policyMappingInhibitPending = policyMappingInhibitPending > _this2.certs[i].extensions[j].parsedValue.inhibitPolicyMapping + 1 ? _this2.certs[i].extensions[j].parsedValue.inhibitPolicyMapping + 1 : policyMappingInhibitPending;
									}
									//endregion
								}
							}
							//endregion

							//region InhibitAnyPolicy
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.54") {
								if (inhibitAnyPolicyIndicator === false) {
									if (_this2.certs[i].extensions[j].parsedValue.valueBlock.valueDec === 0) inhibitAnyPolicyIndicator = true;else {
										if (pendingConstraints[2] === false) {
											pendingConstraints[2] = true;
											inhibitAnyPolicyPending = _this2.certs[i].extensions[j].parsedValue.valueBlock.valueDec;
										} else inhibitAnyPolicyPending = inhibitAnyPolicyPending > _this2.certs[i].extensions[j].parsedValue.valueBlock.valueDec ? _this2.certs[i].extensions[j].parsedValue.valueBlock.valueDec : inhibitAnyPolicyPending;
									}
								}
							}
							//endregion
						}
						//endregion

						//region Check "inhibitAnyPolicyIndicator"
						if (inhibitAnyPolicyIndicator === true) {
							var _policyIndex = -1;

							//region Find "anyPolicy" index
							for (var searchAnyPolicy = 0; searchAnyPolicy < allPolicies.length; searchAnyPolicy++) {
								if (allPolicies[searchAnyPolicy] === "2.5.29.32.0") {
									_policyIndex = searchAnyPolicy;
									break;
								}
							}
							//endregion

							if (_policyIndex !== -1) delete policiesAndCerts[0][i]; // Unset value to "undefined" for "anyPolicies" value for current certificate
						}
						//endregion

						//region Process with "pending constraints"
						if (explicitPolicyIndicator === false) {
							if (pendingConstraints[0] === true) {
								explicitPolicyPending--;
								if (explicitPolicyPending === 0) {
									explicitPolicyIndicator = true;
									explicitPolicyStart = i;

									pendingConstraints[0] = false;
								}
							}
						}

						if (policyMappingInhibitIndicator === false) {
							if (pendingConstraints[1] === true) {
								policyMappingInhibitPending--;
								if (policyMappingInhibitPending === 0) {
									policyMappingInhibitIndicator = true;
									pendingConstraints[1] = false;
								}
							}
						}

						if (inhibitAnyPolicyIndicator === false) {
							if (pendingConstraints[2] === true) {
								inhibitAnyPolicyPending--;
								if (inhibitAnyPolicyPending === 0) {
									inhibitAnyPolicyIndicator = true;
									pendingConstraints[2] = false;
								}
							}
						}
						//endregion
					}
				}
				//endregion

				//region Working with policy mappings
				for (var _i8 = 0; _i8 < _this2.certs.length - 1; _i8++) {
					//region Check that there is "policy mapping" for level "i + 1"
					if (_i8 < _this2.certs.length - 2 && typeof policyMappings[_i8 + 1] !== "undefined") {
						for (var _k = 0; _k < policyMappings[_i8 + 1].mappings.length; _k++) {
							//region Check that we do not have "anyPolicy" in current mapping
							if (policyMappings[_i8 + 1].mappings[_k].issuerDomainPolicy === "2.5.29.32.0" || policyMappings[_i8 + 1].mappings[_k].subjectDomainPolicy === "2.5.29.32.0") {
								return {
									result: false,
									resultCode: 99,
									resultMessage: "The \"anyPolicy\" should not be a part of policy mapping scheme"
								};
							}
							//endregion

							//region Initial variables
							var issuerDomainPolicyIndex = -1;
							var subjectDomainPolicyIndex = -1;
							//endregion

							//region Search for index of policies indedes
							for (var n = 0; n < allPolicies.length; n++) {
								if (allPolicies[n] === policyMappings[_i8 + 1].mappings[_k].issuerDomainPolicy) issuerDomainPolicyIndex = n;

								if (allPolicies[n] === policyMappings[_i8 + 1].mappings[_k].subjectDomainPolicy) subjectDomainPolicyIndex = n;
							}
							//endregion

							//region Delete existing "issuerDomainPolicy" because on the level we mapped the policy to another one
							if (typeof policiesAndCerts[issuerDomainPolicyIndex][_i8] !== "undefined") delete policiesAndCerts[issuerDomainPolicyIndex][_i8];
							//endregion

							//region Check all policies for the certificate
							for (var _j2 = 0; _j2 < certPolicies[_i8].certificatePolicies.length; _j2++) {
								if (policyMappings[_i8 + 1].mappings[_k].subjectDomainPolicy === certPolicies[_i8].certificatePolicies[_j2].policyIdentifier) {
									//region Set mapped policy for current certificate
									if (issuerDomainPolicyIndex !== -1 && subjectDomainPolicyIndex !== -1) {
										for (var m = 0; m <= _i8; m++) {
											if (typeof policiesAndCerts[subjectDomainPolicyIndex][m] !== "undefined") {
												policiesAndCerts[issuerDomainPolicyIndex][m] = true;
												delete policiesAndCerts[subjectDomainPolicyIndex][m];
											}
										}
									}
									//endregion
								}
							}
							//endregion
						}
					}
					//endregion
				}
				//endregion

				//region Working with "explicitPolicyIndicator" and "anyPolicy"
				for (var _i9 = 0; _i9 < allPolicies.length; _i9++) {
					if (allPolicies[_i9] === "2.5.29.32.0") {
						for (var _j3 = 0; _j3 < explicitPolicyStart; _j3++) {
							delete policiesAndCerts[_i9][_j3];
						}
					}
				}
				//endregion

				//region Create "set of authorities-constrained policies"
				var authConstrPolicies = [];

				for (var _i10 = 0; _i10 < policiesAndCerts.length; _i10++) {
					var found = true;

					for (var _j4 = 0; _j4 < _this2.certs.length - 1; _j4++) {
						var anyPolicyFound = false;

						if (_j4 < explicitPolicyStart && allPolicies[_i10] === "2.5.29.32.0" && allPolicies.length > 1) {
							found = false;
							break;
						}

						if (typeof policiesAndCerts[_i10][_j4] === "undefined") {
							if (_j4 >= explicitPolicyStart) {
								//region Search for "anyPolicy" in the policy set
								for (var _k2 = 0; _k2 < allPolicies.length; _k2++) {
									if (allPolicies[_k2] === "2.5.29.32.0") {
										if (policiesAndCerts[_k2][_j4] === true) anyPolicyFound = true;

										break;
									}
								}
								//endregion
							}

							if (!anyPolicyFound) {
								found = false;
								break;
							}
						}
					}

					if (found === true) authConstrPolicies.push(allPolicies[_i10]);
				}
				//endregion

				//region Create "set of user-constrained policies"
				var userConstrPolicies = [];

				if (initialPolicySet.length === 1 && initialPolicySet[0] === "2.5.29.32.0" && explicitPolicyIndicator === false) userConstrPolicies = initialPolicySet;else {
					if (authConstrPolicies.length === 1 && authConstrPolicies[0] === "2.5.29.32.0") userConstrPolicies = initialPolicySet;else {
						for (var _i11 = 0; _i11 < authConstrPolicies.length; _i11++) {
							for (var _j5 = 0; _j5 < initialPolicySet.length; _j5++) {
								if (initialPolicySet[_j5] === authConstrPolicies[_i11] || initialPolicySet[_j5] === "2.5.29.32.0") {
									userConstrPolicies.push(authConstrPolicies[_i11]);
									break;
								}
							}
						}
					}
				}
				//endregion

				//region Combine output object
				return {
					result: userConstrPolicies.length > 0,
					resultCode: 0,
					resultMessage: userConstrPolicies.length > 0 ? "" : "Zero \"userConstrPolicies\" array, no intersections with \"authConstrPolicies\"",
					authConstrPolicies: authConstrPolicies,
					userConstrPolicies: userConstrPolicies,
					explicitPolicyIndicator: explicitPolicyIndicator,
					policyMappings: policyMappings
				};
				//endregion
			});
			//endregion

			//region Work with name constraints
			sequence = sequence.then(function (policyResult) {
				//region Auxiliary functions for name constraints checking
				function compareDNSName(name, constraint) {
					/// <summary>Compare two dNSName values</summary>
					/// <param name="name" type="String">DNS from name</param>
					/// <param name="constraint" type="String">Constraint for DNS from name</param>
					/// <returns type="Boolean">Boolean result - valid or invalid the "name" against the "constraint"</returns>

					//region Make a "string preparation" for both name and constrain
					var namePrepared = (0, _common.stringPrep)(name);
					var constraintPrepared = (0, _common.stringPrep)(constraint);
					//endregion

					//region Make a "splitted" versions of "constraint" and "name"
					var nameSplitted = namePrepared.split(".");
					var constraintSplitted = constraintPrepared.split(".");
					//endregion

					//region Length calculation and additional check
					var nameLen = nameSplitted.length;
					var constrLen = constraintSplitted.length;

					if (nameLen === 0 || constrLen === 0 || nameLen < constrLen) return false;
					//endregion

					//region Check that no part of "name" has zero length
					for (var i = 0; i < nameLen; i++) {
						if (nameSplitted[i].length === 0) return false;
					}
					//endregion

					//region Check that no part of "constraint" has zero length
					for (var _i12 = 0; _i12 < constrLen; _i12++) {
						if (constraintSplitted[_i12].length === 0) {
							if (_i12 === 0) {
								if (constrLen === 1) return false;

								continue;
							}

							return false;
						}
					}
					//endregion

					//region Check that "name" has a tail as "constraint"

					for (var _i13 = 0; _i13 < constrLen; _i13++) {
						if (constraintSplitted[constrLen - 1 - _i13].length === 0) continue;

						if (nameSplitted[nameLen - 1 - _i13].localeCompare(constraintSplitted[constrLen - 1 - _i13]) !== 0) return false;
					}
					//endregion

					return true;
				}

				function compareRFC822Name(name, constraint) {
					/// <summary>Compare two rfc822Name values</summary>
					/// <param name="name" type="String">E-mail address from name</param>
					/// <param name="constraint" type="String">Constraint for e-mail address from name</param>
					/// <returns type="Boolean">Boolean result - valid or invalid the "name" against the "constraint"</returns>

					//region Make a "string preparation" for both name and constrain
					var namePrepared = (0, _common.stringPrep)(name);
					var constraintPrepared = (0, _common.stringPrep)(constraint);
					//endregion

					//region Make a "splitted" versions of "constraint" and "name"
					var nameSplitted = namePrepared.split("@");
					var constraintSplitted = constraintPrepared.split("@");
					//endregion

					//region Splitted array length checking
					if (nameSplitted.length === 0 || constraintSplitted.length === 0 || nameSplitted.length < constraintSplitted.length) return false;
					//endregion

					if (constraintSplitted.length === 1) {
						var result = compareDNSName(nameSplitted[1], constraintSplitted[0]);

						if (result) {
							//region Make a "splitted" versions of domain name from "constraint" and "name"
							var ns = nameSplitted[1].split(".");
							var cs = constraintSplitted[0].split(".");
							//endregion

							if (cs[0].length === 0) return true;

							return ns.length === cs.length;
						}

						return false;
					}

					return namePrepared.localeCompare(constraintPrepared) === 0;
				}

				function compareUniformResourceIdentifier(name, constraint) {
					/// <summary>Compare two uniformResourceIdentifier values</summary>
					/// <param name="name" type="String">uniformResourceIdentifier from name</param>
					/// <param name="constraint" type="String">Constraint for uniformResourceIdentifier from name</param>
					/// <returns type="Boolean">Boolean result - valid or invalid the "name" against the "constraint"</returns>

					//region Make a "string preparation" for both name and constrain
					var namePrepared = (0, _common.stringPrep)(name);
					var constraintPrepared = (0, _common.stringPrep)(constraint);
					//endregion

					//region Find out a major URI part to compare with
					var ns = namePrepared.split("/");
					var cs = constraintPrepared.split("/");

					if (cs.length > 1) // Malformed constraint
						return false;

					if (ns.length > 1) // Full URI string
						{
							for (var i = 0; i < ns.length; i++) {
								if (ns[i].length > 0 && ns[i].charAt(ns[i].length - 1) !== ":") {
									var nsPort = ns[i].split(":");
									namePrepared = nsPort[0];
									break;
								}
							}
						}
					//endregion

					var result = compareDNSName(namePrepared, constraintPrepared);

					if (result) {
						//region Make a "splitted" versions of "constraint" and "name"
						var nameSplitted = namePrepared.split(".");
						var constraintSplitted = constraintPrepared.split(".");
						//endregion

						if (constraintSplitted[0].length === 0) return true;

						return nameSplitted.length === constraintSplitted.length;
					}

					return false;
				}

				function compareIPAddress(name, constraint) {
					/// <summary>Compare two iPAddress values</summary>
					/// <param name="name" type="in_window.org.pkijs.asn1.OCTETSTRING">iPAddress from name</param>
					/// <param name="constraint" type="in_window.org.pkijs.asn1.OCTETSTRING">Constraint for iPAddress from name</param>
					/// <returns type="Boolean">Boolean result - valid or invalid the "name" against the "constraint"</returns>

					//region Common variables
					var nameView = new Uint8Array(name.valueBlock.valueHex);
					var constraintView = new Uint8Array(constraint.valueBlock.valueHex);
					//endregion

					//region Work with IPv4 addresses
					if (nameView.length === 4 && constraintView.length === 8) {
						for (var i = 0; i < 4; i++) {
							if ((nameView[i] ^ constraintView[i]) & constraintView[i + 4]) return false;
						}

						return true;
					}
					//endregion

					//region Work with IPv6 addresses
					if (nameView.length === 16 && constraintView.length === 32) {
						for (var _i14 = 0; _i14 < 16; _i14++) {
							if ((nameView[_i14] ^ constraintView[_i14]) & constraintView[_i14 + 16]) return false;
						}

						return true;
					}
					//endregion

					return false;
				}

				function compareDirectoryName(name, constraint) {
					/// <summary>Compare two directoryName values</summary>
					/// <param name="name" type="in_window.org.pkijs.simpl.RDN">directoryName from name</param>
					/// <param name="constraint" type="in_window.org.pkijs.simpl.RDN">Constraint for directoryName from name</param>
					/// <param name="any" type="Boolean">Boolean flag - should be comparision interrupted after first match or we need to match all "constraints" parts</param>
					/// <returns type="Boolean">Boolean result - valid or invalid the "name" against the "constraint"</returns>

					//region Initial check
					if (name.typesAndValues.length === 0 || constraint.typesAndValues.length === 0) return true;

					if (name.typesAndValues.length < constraint.typesAndValues.length) return false;
					//endregion

					//region Initial variables
					var result = true;
					var nameStart = 0;
					//endregion

					for (var i = 0; i < constraint.typesAndValues.length; i++) {
						var localResult = false;

						for (var j = nameStart; j < name.typesAndValues.length; j++) {
							localResult = name.typesAndValues[j].isEqual(constraint.typesAndValues[i]);

							if (name.typesAndValues[j].type === constraint.typesAndValues[i].type) result = result && localResult;

							if (localResult === true) {
								if (nameStart === 0 || nameStart === j) {
									nameStart = j + 1;
									break;
								} else // Structure of "name" must be the same with "constraint"
									return false;
							}
						}

						if (localResult === false) return false;
					}

					return nameStart === 0 ? false : result;
				}
				//endregion

				//region Check a result from "policy checking" part
				if (policyResult.result === false) return policyResult;
				//endregion

				//region Check all certificates, excluding "trust anchor"
				pathDepth = 1;

				for (var i = _this2.certs.length - 2; i >= 0; i--, pathDepth++) {
					//region Support variables
					var subjectAltNames = [];

					var certPermittedSubtrees = [];
					var certExcludedSubtrees = [];
					//endregion

					if ("extensions" in _this2.certs[i]) {
						for (var j = 0; j < _this2.certs[i].extensions.length; j++) {
							//region NameConstraints
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.30") {
								if ("permittedSubtrees" in _this2.certs[i].extensions[j].parsedValue) certPermittedSubtrees = certPermittedSubtrees.concat(_this2.certs[i].extensions[j].parsedValue.permittedSubtrees);

								if ("excludedSubtrees" in _this2.certs[i].extensions[j].parsedValue) certExcludedSubtrees = certExcludedSubtrees.concat(_this2.certs[i].extensions[j].parsedValue.excludedSubtrees);
							}
							//endregion

							//region SubjectAltName
							if (_this2.certs[i].extensions[j].extnID === "2.5.29.17") subjectAltNames = subjectAltNames.concat(_this2.certs[i].extensions[j].parsedValue.altNames);
							//endregion
						}
					}

					//region Checking for "required name forms"
					var formFound = requiredNameForms.length <= 0;

					for (var _j6 = 0; _j6 < requiredNameForms.length; _j6++) {
						switch (requiredNameForms[_j6].base.type) {
							case 4:
								// directoryName
								{
									if (requiredNameForms[_j6].base.value.typesAndValues.length !== _this2.certs[i].subject.typesAndValues.length) continue;

									formFound = true;

									for (var k = 0; k < _this2.certs[i].subject.typesAndValues.length; k++) {
										if (_this2.certs[i].subject.typesAndValues[k].type !== requiredNameForms[_j6].base.value.typesAndValues[k].type) {
											formFound = false;
											break;
										}
									}

									if (formFound === true) break;
								}
								break;
							default: // ??? Probably here we should reject the certificate ???
						}
					}

					if (formFound === false) {
						policyResult.result = false;
						policyResult.resultCode = 21;
						policyResult.resultMessage = "No neccessary name form found";

						return Promise.reject(policyResult);
					}
					//endregion

					//region Checking for "permited sub-trees"
					//region Make groups for all types of constraints
					var constrGroups = []; // Array of array for groupped constraints
					constrGroups[0] = []; // rfc822Name
					constrGroups[1] = []; // dNSName
					constrGroups[2] = []; // directoryName
					constrGroups[3] = []; // uniformResourceIdentifier
					constrGroups[4] = []; // iPAddress

					for (var _j7 = 0; _j7 < permittedSubtrees.length; _j7++) {
						switch (permittedSubtrees[_j7].base.type) {
							//region rfc822Name
							case 1:
								constrGroups[0].push(permittedSubtrees[_j7]);
								break;
							//endregion
							//region dNSName
							case 2:
								constrGroups[1].push(permittedSubtrees[_j7]);
								break;
							//endregion
							//region directoryName
							case 4:
								constrGroups[2].push(permittedSubtrees[_j7]);
								break;
							//endregion
							//region uniformResourceIdentifier
							case 6:
								constrGroups[3].push(permittedSubtrees[_j7]);
								break;
							//endregion
							//region iPAddress
							case 7:
								constrGroups[4].push(permittedSubtrees[_j7]);
								break;
							//endregion
							//region default
							default:
							//endregion
						}
					}
					//endregion

					//region Check name constraints groupped by type, one-by-one
					for (var p = 0; p < 5; p++) {
						var groupPermitted = false;
						var valueExists = false;
						var group = constrGroups[p];

						for (var _j8 = 0; _j8 < group.length; _j8++) {
							switch (p) {
								//region rfc822Name
								case 0:
									if (subjectAltNames.length > 0) {
										for (var _k3 = 0; _k3 < subjectAltNames.length; _k3++) {
											if (subjectAltNames[_k3].type === 1) // rfc822Name
												{
													valueExists = true;
													groupPermitted = groupPermitted || compareRFC822Name(subjectAltNames[_k3].value, group[_j8].base.value);
												}
										}
									} else // Try to find out "emailAddress" inside "subject"
										{
											for (var _k4 = 0; _k4 < _this2.certs[i].subject.typesAndValues.length; _k4++) {
												if (_this2.certs[i].subject.typesAndValues[_k4].type === "1.2.840.113549.1.9.1" || // PKCS#9 e-mail address
												_this2.certs[i].subject.typesAndValues[_k4].type === "0.9.2342.19200300.100.1.3") // RFC1274 "rfc822Mailbox" e-mail address
													{
														valueExists = true;
														groupPermitted = groupPermitted || compareRFC822Name(_this2.certs[i].subject.typesAndValues[_k4].value.valueBlock.value, group[_j8].base.value);
													}
											}
										}
									break;
								//endregion
								//region dNSName
								case 1:
									if (subjectAltNames.length > 0) {
										for (var _k5 = 0; _k5 < subjectAltNames.length; _k5++) {
											if (subjectAltNames[_k5].type === 2) // dNSName
												{
													valueExists = true;
													groupPermitted = groupPermitted || compareDNSName(subjectAltNames[_k5].value, group[_j8].base.value);
												}
										}
									}
									break;
								//endregion
								//region directoryName
								case 2:
									valueExists = true;
									groupPermitted = compareDirectoryName(_this2.certs[i].subject, group[_j8].base.value);
									break;
								//endregion
								//region uniformResourceIdentifier
								case 3:
									if (subjectAltNames.length > 0) {
										for (var _k6 = 0; _k6 < subjectAltNames.length; _k6++) {
											if (subjectAltNames[_k6].type === 6) // uniformResourceIdentifier
												{
													valueExists = true;
													groupPermitted = groupPermitted || compareUniformResourceIdentifier(subjectAltNames[_k6].value, group[_j8].base.value);
												}
										}
									}
									break;
								//endregion
								//region iPAddress
								case 4:
									if (subjectAltNames.length > 0) {
										for (var _k7 = 0; _k7 < subjectAltNames.length; _k7++) {
											if (subjectAltNames[_k7].type === 7) // iPAddress
												{
													valueExists = true;
													groupPermitted = groupPermitted || compareIPAddress(subjectAltNames[_k7].value, group[_j8].base.value);
												}
										}
									}
									break;
								//endregion
								//region default
								default:
								//endregion
							}

							if (groupPermitted) break;
						}

						if (groupPermitted === false && group.length > 0 && valueExists) {
							policyResult.result = false;
							policyResult.resultCode = 41;
							policyResult.resultMessage = "Failed to meet \"permitted sub-trees\" name constraint";

							return Promise.reject(policyResult);
						}
					}
					//endregion
					//endregion

					//region Checking for "excluded sub-trees"
					var excluded = false;

					for (var _j9 = 0; _j9 < excludedSubtrees.length; _j9++) {
						switch (excludedSubtrees[_j9].base.type) {
							//region rfc822Name
							case 1:
								if (subjectAltNames.length >= 0) {
									for (var _k8 = 0; _k8 < subjectAltNames.length; _k8++) {
										if (subjectAltNames[_k8].type === 1) // rfc822Name
											excluded = excluded || compareRFC822Name(subjectAltNames[_k8].value, excludedSubtrees[_j9].base.value);
									}
								} else // Try to find out "emailAddress" inside "subject"
									{
										for (var _k9 = 0; _k9 < _this2.subject.typesAndValues.length; _k9++) {
											if (_this2.subject.typesAndValues[_k9].type === "1.2.840.113549.1.9.1" || // PKCS#9 e-mail address
											_this2.subject.typesAndValues[_k9].type === "0.9.2342.19200300.100.1.3") // RFC1274 "rfc822Mailbox" e-mail address
												excluded = excluded || compareRFC822Name(_this2.subject.typesAndValues[_k9].value.valueBlock.value, excludedSubtrees[_j9].base.value);
										}
									}
								break;
							//endregion
							//region dNSName
							case 2:
								if (subjectAltNames.length > 0) {
									for (var _k10 = 0; _k10 < subjectAltNames.length; _k10++) {
										if (subjectAltNames[_k10].type === 2) // dNSName
											excluded = excluded || compareDNSName(subjectAltNames[_k10].value, excludedSubtrees[_j9].base.value);
									}
								}
								break;
							//endregion
							//region directoryName
							case 4:
								excluded = excluded || compareDirectoryName(_this2.certs[i].subject, excludedSubtrees[_j9].base.value);
								break;
							//endregion
							//region uniformResourceIdentifier
							case 6:
								if (subjectAltNames.length > 0) {
									for (var _k11 = 0; _k11 < subjectAltNames.length; _k11++) {
										if (subjectAltNames[_k11].type === 6) // uniformResourceIdentifier
											excluded = excluded || compareUniformResourceIdentifier(subjectAltNames[_k11].value, excludedSubtrees[_j9].base.value);
									}
								}
								break;
							//endregion
							//region iPAddress
							case 7:
								if (subjectAltNames.length > 0) {
									for (var _k12 = 0; _k12 < subjectAltNames.length; _k12++) {
										if (subjectAltNames[_k12].type === 7) // iPAddress
											excluded = excluded || compareIPAddress(subjectAltNames[_k12].value, excludedSubtrees[_j9].base.value);
									}
								}
								break;
							//endregion
							//region default
							default: // No action, but probably here we need to create a warning for "malformed constraint"
							//endregion
						}

						if (excluded) break;
					}

					if (excluded === true) {
						policyResult.result = false;
						policyResult.resultCode = 42;
						policyResult.resultMessage = "Failed to meet \"excluded sub-trees\" name constraint";

						return Promise.reject(policyResult);
					}
					//endregion

					//region Append "cert_..._subtrees" to "..._subtrees"
					permittedSubtrees = permittedSubtrees.concat(certPermittedSubtrees);
					excludedSubtrees = excludedSubtrees.concat(certExcludedSubtrees);
					//endregion
				}
				//endregion

				return policyResult;
			});
			//endregion

			//region Error handling stub
			sequence = sequence.then(function (result) {
				return result;
			}, function (error) {
				return {
					result: false,
					resultCode: -1,
					resultMessage: error.message
				};
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "trustedCerts":
					return [];
				case "certs":
					return [];
				case "crls":
					return [];
				case "ocsps":
					return [];
				case "checkDate":
					return new Date();
				default:
					throw new Error("Invalid member name for CertificateChainValidationEngine class: " + memberName);
			}
		}
	}]);

	return CertificateChainValidationEngine;
}();
//**************************************************************************************


exports.default = CertificateChainValidationEngine;
//# sourceMappingURL=CertificateChainValidationEngine.js.map