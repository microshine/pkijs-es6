"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _ContentInfo = require("./ContentInfo");

var _ContentInfo2 = _interopRequireDefault(_ContentInfo);

var _SafeContents = require("./SafeContents");

var _SafeContents2 = _interopRequireDefault(_SafeContents);

var _EnvelopedData = require("./EnvelopedData");

var _EnvelopedData2 = _interopRequireDefault(_EnvelopedData);

var _EncryptedData = require("./EncryptedData");

var _EncryptedData2 = _interopRequireDefault(_EncryptedData);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var AuthenticatedSafe = function () {
	//**********************************************************************************
	/**
  * Constructor for AuthenticatedSafe class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function AuthenticatedSafe() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, AuthenticatedSafe);

		//region Internal properties of the object
		/**
   * @type {Array.<ContentInfo>}
   * @description safeContents
   */
		this.safeContents = (0, _pvutils.getParametersValue)(parameters, "safeContents", AuthenticatedSafe.defaultValues("safeContents"));

		if ("parsedValue" in parameters) {
			/**
    * @type {*}
    * @description parsedValue
    */
			this.parsedValue = (0, _pvutils.getParametersValue)(parameters, "parsedValue", AuthenticatedSafe.defaultValues("parsedValue"));
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


	_createClass(AuthenticatedSafe, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, AuthenticatedSafe.schema({
				names: {
					contentInfos: "contentInfos"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for AuthenticatedSafe");
			//endregion

			//region Get internal properties from parsed schema
			this.safeContents = Array.from(asn1.result.contentInfos, function (element) {
				return new _ContentInfo2.default({ schema: element });
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
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: Array.from(this.safeContents, function (element) {
					return element.toSchema();
				})
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
			return {
				safeContents: Array.from(this.safeContents, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}, {
		key: "parseInternalValues",
		value: function parseInternalValues(parameters) {
			var _this = this;

			//region Check input data from "parameters"
			if (parameters instanceof Object == false) return Promise.reject("The \"parameters\" must has \"Object\" type");

			if ("safeContents" in parameters == false) return Promise.reject("Absent mandatory parameter \"safeContents\"");

			if (parameters.safeContents instanceof Array == false) return Promise.reject("The \"parameters.safeContents\" must has \"Array\" type");

			if (parameters.safeContents.length != this.safeContents.length) return Promise.reject("Length of \"parameters.safeContents\" must be equal to \"this.safeContents.length\"");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();
			//endregion

			//region Create value for "this.parsedValue.authenticatedSafe"
			this.parsedValue = {
				safeContents: []
			};

			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = this.safeContents.entries()[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var _step$value = _slicedToArray(_step.value, 2);

					var index = _step$value[0];
					var content = _step$value[1];

					switch (content.contentType) {
						//region data
						case "1.2.840.113549.1.7.1":
							{
								//region Check that we do have OCTETSTRING as "content"
								if (content.content instanceof asn1js.OctetString == false) return Promise.reject("Wrong type of \"this.safeContents[j].content\"");
								//endregion

								//region Parse internal ASN.1 data
								var asn1 = asn1js.fromBER(content.content.valueBlock.valueHex);
								if (asn1.offset == -1) return Promise.reject("Error during parsing of ASN.1 data inside \"content.content\"");
								//endregion

								//region Finilly initialize initial values of "SafeContents" type
								this.parsedValue.safeContents.push({
									privacyMode: 0, // No privacy, clear data
									value: new _SafeContents2.default({ schema: asn1.result })
								});
								//endregion
							}
							break;
						//endregion
						//region envelopedData
						case "1.2.840.113549.1.7.3":
							{
								var _ret = function () {
									//region Initial variables
									var cmsEnveloped = new _EnvelopedData2.default({ schema: content.content });
									//endregion

									//region Check mandatory parameters
									if ("recipientCertificate" in parameters.safeContents[index] == false) return {
											v: Promise.reject("Absent mandatory parameter \"recipientCertificate\" in \"parameters.safeContents[j]\"")
										};

									var recipientCertificate = parameters.safeContents[index].recipientCertificate;

									if ("recipientKey" in parameters.safeContents[index] == false) return {
											v: Promise.reject("Absent mandatory parameter \"recipientKey\" in \"parameters.safeContents[j]\"")
										};

									var recipientKey = parameters.safeContents[index].recipientKey;
									//endregion

									//region Decrypt CMS EnvelopedData using first recipient information
									sequence = sequence.then(function () {
										return cmsEnveloped.decrypt(0, {
											recipientCertificate: recipientCertificate,
											recipientPrivateKey: recipientKey
										});
									});

									sequence = sequence.then(function (result) {
										var asn1 = asn1js.fromBER(result);
										if (asn1.offset == -1) return Promise.reject("Error during parsing of decrypted data");

										_this.parsedValue.safeContents.push({
											privacyMode: 2, // Public-key privacy mode
											value: new _SafeContents2.default({ schema: asn1.result })
										});
									});
									//endregion
								}();

								if ((typeof _ret === "undefined" ? "undefined" : _typeof(_ret)) === "object") return _ret.v;
							}
							break;
						//endregion  
						//region encryptedData
						case "1.2.840.113549.1.7.6":
							{
								var _ret2 = function () {
									//region Initial variables
									var cmsEncrypted = new _EncryptedData2.default({ schema: content.content });
									//endregion

									//region Check mandatory parameters
									if ("password" in parameters.safeContents[index] == false) return {
											v: Promise.reject("Absent mandatory parameter \"password\" in \"parameters.safeContents[j]\"")
										};

									var password = parameters.safeContents[index].password;
									//endregion

									//region Decrypt CMS EncryptedData using password
									sequence = sequence.then(function () {
										return cmsEncrypted.decrypt({
											password: password
										});
									}, function (error) {
										return Promise.reject(error);
									});
									//endregion

									//region Initialize internal data
									sequence = sequence.then(function (result) {
										var asn1 = asn1js.fromBER(result);
										if (asn1.offset == -1) return Promise.reject("Error during parsing of decrypted data");

										_this.parsedValue.safeContents.push({
											privacyMode: 1, // Password-based privacy mode
											value: new _SafeContents2.default({ schema: asn1.result })
										});
									}, function (error) {
										return Promise.reject(error);
									});
									//endregion
								}();

								if ((typeof _ret2 === "undefined" ? "undefined" : _typeof(_ret2)) === "object") return _ret2.v;
							}
							break;
						//endregion  
						//region default
						default:
							throw new Error("Unknown \"contentType\" for AuthenticatedSafe: \" " + content.contentType);
						//endregion
					}
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

			return sequence;
		}
		//**********************************************************************************

	}, {
		key: "makeInternalValues",
		value: function makeInternalValues(parameters) {
			var _this2 = this;

			//region Check data in "parsedValue"
			if ("parsedValue" in this == false) return Promise.reject("Please run \"parseValues\" first or add \"parsedValue\" manually");

			if (this.parsedValue instanceof Object == false) return Promise.reject("The \"this.parsedValue\" must has \"Object\" type");

			if (this.parsedValue.safeContents instanceof Array == false) return Promise.reject("The \"this.parsedValue.safeContents\" must has \"Array\" type");
			//endregion

			//region Check input data from "parameters"
			if (parameters instanceof Object == false) return Promise.reject("The \"parameters\" must has \"Object\" type");

			if ("safeContents" in parameters == false) return Promise.reject("Absent mandatory parameter \"safeContents\"");

			if (parameters.safeContents instanceof Array == false) return Promise.reject("The \"parameters.safeContents\" must has \"Array\" type");

			if (parameters.safeContents.length != this.parsedValue.safeContents.length) return Promise.reject("Length of \"parameters.safeContents\" must be equal to \"this.parsedValue.safeContents\"");
			//endregion

			//region Initial variables
			var sequence = Promise.resolve();
			//endregion

			//region Create internal values from already parsed values
			this.safeContents = [];

			var _iteratorNormalCompletion2 = true;
			var _didIteratorError2 = false;
			var _iteratorError2 = undefined;

			try {
				for (var _iterator2 = this.parsedValue.safeContents.entries()[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
					var _step2$value = _slicedToArray(_step2.value, 2);

					var index = _step2$value[0];
					var content = _step2$value[1];

					//region Check current "content" value
					if ("privacyMode" in content == false) return Promise.reject("The \"privacyMode\" is a mandatory parameter for \"content\"");

					if ("value" in content == false) return Promise.reject("The \"value\" is a mandatory parameter for \"content\"");

					if (content.value instanceof _SafeContents2.default == false) return Promise.reject("The \"content.value\" must has \"SafeContents\" type");
					//endregion

					switch (content.privacyMode) {
						//region No privacy
						case 0:
							{
								(function () {
									var contentBuffer = content.value.toSchema().toBER(false);

									sequence = sequence.then(function () {
										_this2.safeContents.push(new _ContentInfo2.default({
											contentType: "1.2.840.113549.1.7.1",
											content: new asn1js.OctetString({ valueHex: contentBuffer })
										}));
									});
								})();
							}
							break;
						//endregion
						//region Privacy with password
						case 1:
							{
								(function () {
									//region Initial variables
									var cmsEncrypted = new _EncryptedData2.default();

									var currentParameters = parameters.safeContents[index];
									currentParameters.contentToEncrypt = content.value.toSchema().toBER(false);
									//endregion

									//region Encrypt CMS EncryptedData using password
									sequence = sequence.then(function () {
										return cmsEncrypted.encrypt(currentParameters);
									}, function (error) {
										return Promise.reject(error);
									});
									//endregion

									//region Store result content in CMS_CONTENT_INFO type
									sequence = sequence.then(function () {
										_this2.safeContents.push(new _ContentInfo2.default({
											contentType: "1.2.840.113549.1.7.6",
											content: cmsEncrypted.toSchema()
										}));
									}, function (error) {
										return Promise.reject(error);
									});
									//endregion
								})();
							}
							break;
						//endregion
						//region Privacy with public key
						case 2:
							{
								var _ret5 = function () {
									//region Initial variables
									var cmsEnveloped = new _EnvelopedData2.default();
									var contentToEncrypt = content.value.toSchema().toBER(false);
									//endregion

									//region Check mandatory parameters
									if ("encryptingCertificate" in parameters.safeContents[index] == false) return {
											v: Promise.reject("Absent mandatory parameter \"encryptingCertificate\" in \"parameters.safeContents[i]\"")
										};

									if ("encryptionAlgorithm" in parameters.safeContents[index] == false) return {
											v: Promise.reject("Absent mandatory parameter \"encryptionAlgorithm\" in \"parameters.safeContents[i]\"")
										};

									switch (true) {
										case parameters.safeContents[index].encryptionAlgorithm.name.toLowerCase() == "aes-cbc":
										case parameters.safeContents[index].encryptionAlgorithm.name.toLowerCase() == "aes-gcm":
											break;
										default:
											return {
												v: Promise.reject("Incorrect parameter \"encryptionAlgorithm\" in \"parameters.safeContents[i]\": " + parameters.safeContents[index].encryptionAlgorithm)
											};
									}

									switch (true) {
										case parameters.safeContents[index].encryptionAlgorithm.length == 128:
										case parameters.safeContents[index].encryptionAlgorithm.length == 192:
										case parameters.safeContents[index].encryptionAlgorithm.length == 256:
											break;
										default:
											return {
												v: Promise.reject("Incorrect parameter \"encryptionAlgorithm.length\" in \"parameters.safeContents[i]\": " + parameters.safeContents[index].encryptionAlgorithm.length)
											};
									}
									//endregion

									//region Making correct "encryptionAlgorithm" variable
									var encryptionAlgorithm = parameters.safeContents[index].encryptionAlgorithm;
									//endregion

									//region Append recipient for enveloped data
									cmsEnveloped.addRecipientByCertificate(parameters.safeContents[index].encryptingCertificate);
									//endregion

									//region Making encryption
									sequence = sequence.then(function () {
										return cmsEnveloped.encrypt(encryptionAlgorithm, contentToEncrypt);
									});

									sequence = sequence.then(function () {
										_this2.safeContents.push(new _ContentInfo2.default({
											contentType: "1.2.840.113549.1.7.3",
											content: cmsEnveloped.toSchema()
										}));
									});
									//endregion
								}();

								if ((typeof _ret5 === "undefined" ? "undefined" : _typeof(_ret5)) === "object") return _ret5.v;
							}
							break;
						//endregion
						//region default
						default:
							return Promise.reject("Incorrect value for \"content.privacyMode\": " + content.privacyMode);
						//endregion
					}
				}
				//endregion

				//region Return result of the function
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
				case "safeContents":
					return [];
				case "parsedValue":
					return {};
				default:
					throw new Error("Invalid member name for AuthenticatedSafe class: " + memberName);
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
				case "safeContents":
					return memberValue.length === 0;
				case "parsedValue":
					return memberValue instanceof Object && Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for AuthenticatedSafe class: " + memberName);
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

			//AuthenticatedSafe ::= SEQUENCE OF ContentInfo
			//-- Data if unencrypted
			//-- EncryptedData if password-encrypted
			//-- EnvelopedData if public key-encrypted

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [contentInfos]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.contentInfos || "",
					value: _ContentInfo2.default.schema()
				})]
			});
		}
	}]);

	return AuthenticatedSafe;
}();
//**************************************************************************************


exports.default = AuthenticatedSafe;
//# sourceMappingURL=AuthenticatedSafe.js.map