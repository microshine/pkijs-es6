"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _MessageImprint = require("./MessageImprint");

var _MessageImprint2 = _interopRequireDefault(_MessageImprint);

var _Accuracy = require("./Accuracy");

var _Accuracy2 = _interopRequireDefault(_Accuracy);

var _GeneralName = require("./GeneralName");

var _GeneralName2 = _interopRequireDefault(_GeneralName);

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var TSTInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for TSTInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function TSTInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, TSTInfo);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", TSTInfo.defaultValues("version"));
		/**
   * @type {string}
   * @description policy
   */
		this.policy = (0, _pvutils.getParametersValue)(parameters, "policy", TSTInfo.defaultValues("policy"));
		/**
   * @type {MessageImprint}
   * @description messageImprint
   */
		this.messageImprint = (0, _pvutils.getParametersValue)(parameters, "messageImprint", TSTInfo.defaultValues("messageImprint"));
		/**
   * @type {Integer}
   * @description serialNumber
   */
		this.serialNumber = (0, _pvutils.getParametersValue)(parameters, "serialNumber", TSTInfo.defaultValues("serialNumber"));
		/**
   * @type {Date}
   * @description genTime
   */
		this.genTime = (0, _pvutils.getParametersValue)(parameters, "genTime", TSTInfo.defaultValues("genTime"));

		if ("accuracy" in parameters)
			/**
    * @type {Accuracy}
    * @description accuracy
    */
			this.accuracy = (0, _pvutils.getParametersValue)(parameters, "accuracy", TSTInfo.defaultValues("accuracy"));

		if ("ordering" in parameters)
			/**
    * @type {boolean}
    * @description ordering
    */
			this.ordering = (0, _pvutils.getParametersValue)(parameters, "ordering", TSTInfo.defaultValues("ordering"));

		if ("nonce" in parameters)
			/**
    * @type {Integer}
    * @description nonce
    */
			this.nonce = (0, _pvutils.getParametersValue)(parameters, "nonce", TSTInfo.defaultValues("nonce"));

		if ("tsa" in parameters)
			/**
    * @type {GeneralName}
    * @description tsa
    */
			this.tsa = (0, _pvutils.getParametersValue)(parameters, "tsa", TSTInfo.defaultValues("tsa"));

		if ("extensions" in parameters)
			/**
    * @type {Array.<Extension>}
    * @description extensions
    */
			this.extensions = (0, _pvutils.getParametersValue)(parameters, "extensions", TSTInfo.defaultValues("extensions"));
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


	_createClass(TSTInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, TSTInfo.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for TST_INFO");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result["TSTInfo.version"].valueBlock.valueDec;
			this.policy = asn1.result["TSTInfo.policy"].valueBlock.toString();
			this.messageImprint = new _MessageImprint2.default({ schema: asn1.result["TSTInfo.messageImprint"] });
			this.serialNumber = asn1.result["TSTInfo.serialNumber"];
			this.genTime = asn1.result["TSTInfo.genTime"].toDate();
			if ("TSTInfo.accuracy" in asn1.result) this.accuracy = new _Accuracy2.default({ schema: asn1.result["TSTInfo.accuracy"] });
			if ("TSTInfo.ordering" in asn1.result) this.ordering = asn1.result["TSTInfo.ordering"].valueBlock.value;
			if ("TSTInfo.nonce" in asn1.result) this.nonce = asn1.result["TSTInfo.nonce"];
			if ("TSTInfo.tsa" in asn1.result) this.tsa = new _GeneralName2.default({ schema: asn1.result["TSTInfo.tsa"] });
			if ("TSTInfo.extensions" in asn1.result) this.extensions = Array.from(asn1.result["TSTInfo.extensions"], function (element) {
				return new _Extension2.default({ schema: element });
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
			outputArray.push(new asn1js.ObjectIdentifier({ value: this.policy }));
			outputArray.push(this.messageImprint.toSchema());
			outputArray.push(this.serialNumber);
			outputArray.push(new asn1js.GeneralizedTime({ valueDate: this.genTime }));
			if ("accuracy" in this) outputArray.push(this.accuracy.toSchema());
			if ("ordering" in this) outputArray.push(new asn1js.Boolean({ value: this.ordering }));
			if ("nonce" in this) outputArray.push(this.nonce);
			if ("tsa" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.tsa.toSchema()]
				}));
			}

			//region Create array of extensions
			if ("extensions" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: Array.from(this.extensions, function (element) {
						return element.toSchema();
					})
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
				version: this.version,
				policy: this.policy,
				messageImprint: this.messageImprint.toJSON(),
				serialNumber: this.serialNumber.toJSON(),
				genTime: this.genTime
			};

			if ("accuracy" in this) _object.accuracy = this.accuracy.toJSON();

			if ("ordering" in this) _object.ordering = this.ordering;

			if ("nonce" in this) _object.nonce = this.nonce.toJSON();

			if ("tsa" in this) _object.tsa = this.tsa.toJSON();

			if ("extensions" in this) _object.extensions = Array.from(this.extensions, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************
		/**
   * Verify current TST Info value
   * @param {{data: ArrayBuffer, notBefore: Date, notAfter: Date}} parameters Input parameters
   * @returns {Promise}
   */

	}, {
		key: "verify",
		value: function verify() {
			var _this = this;

			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//region Initial variables
			var sequence = Promise.resolve();

			var data = void 0;

			var notBefore = void 0;
			var notAfter = void 0;
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Get initial parameters
			if ("data" in parameters) data = parameters.data;else return Promise.reject("\"data\" is a mandatory attribute for TST_INFO verification");

			if ("notBefore" in parameters) notBefore = parameters.notBefore;

			if ("notAfter" in parameters) notAfter = parameters.notAfter;
			//endregion

			//region Find hashing algorithm
			var shaAlgorithm = (0, _common.getAlgorithmByOID)(this.messageImprint.hashAlgorithm.algorithmId);
			if ("name" in shaAlgorithm === false) return Promise.reject("Unsupported signature algorithm: " + this.messageImprint.hashAlgorithm.algorithmId);
			//endregion

			//region Calculate message digest for input "data" buffer
			sequence = sequence.then(function () {
				return crypto.digest(shaAlgorithm.name, new Uint8Array(data));
			}).then(function (result) {
				return (0, _pvutils.isEqualBuffer)(result, _this.messageImprint.hashedMessage.valueBlock.valueHex);
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
				case "policy":
					return "";
				case "messageImprint":
					return new _MessageImprint2.default();
				case "serialNumber":
					return new asn1js.Integer();
				case "genTime":
					return new Date(0, 0, 0);
				case "accuracy":
					return new _Accuracy2.default();
				case "ordering":
					return false;
				case "nonce":
					return new asn1js.Integer();
				case "tsa":
					return new _GeneralName2.default();
				case "extensions":
					return [];
				default:
					throw new Error("Invalid member name for TSTInfo class: " + memberName);
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
				case "policy":
				case "genTime":
				case "ordering":
					return memberValue === TSTInfo.defaultValues(memberName);
				case "messageImprint":
					return _MessageImprint2.default.compareWithDefault("hashAlgorithm", memberValue.hashAlgorithm) && _MessageImprint2.default.compareWithDefault("hashedMessage", memberValue.hashedMessage);
				case "serialNumber":
				case "nonce":
					return memberValue.isEqual(TSTInfo.defaultValues(memberName));
				case "accuracy":
					return _Accuracy2.default.compareWithDefault("seconds", memberValue.seconds) && _Accuracy2.default.compareWithDefault("millis", memberValue.millis) && _Accuracy2.default.compareWithDefault("micros", memberValue.micros);
				case "tsa":
					return _GeneralName2.default.compareWithDefault("type", memberValue.type) && _GeneralName2.default.compareWithDefault("value", memberValue.value);
				case "extensions":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for TSTInfo class: " + memberName);
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

			//TSTInfo ::= SEQUENCE  {
			//   version                      INTEGER  { v1(1) },
			//   policy                       TSAPolicyId,
			//   messageImprint               MessageImprint,
			//   serialNumber                 INTEGER,
			//   genTime                      GeneralizedTime,
			//   accuracy                     Accuracy                 OPTIONAL,
			//   ordering                     BOOLEAN             DEFAULT FALSE,
			//   nonce                        INTEGER                  OPTIONAL,
			//   tsa                          [0] GeneralName          OPTIONAL,
			//   extensions                   [1] IMPLICIT Extensions  OPTIONAL  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [policy]
    * @property {string} [messageImprint]
    * @property {string} [serialNumber]
    * @property {string} [genTime]
    * @property {string} [accuracy]
    * @property {string} [ordering]
    * @property {string} [nonce]
    * @property {string} [tsa]
    * @property {string} [extensions]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "TSTInfo",
				value: [new asn1js.Integer({ name: names.version || "TSTInfo.version" }), new asn1js.ObjectIdentifier({ name: names.policy || "TSTInfo.policy" }), _MessageImprint2.default.schema(names.messageImprint || {
					names: {
						blockName: "TSTInfo.messageImprint"
					}
				}), new asn1js.Integer({ name: names.serialNumber || "TSTInfo.serialNumber" }), new asn1js.GeneralizedTime({ name: names.genTime || "TSTInfo.genTime" }), _Accuracy2.default.schema(names.accuracy || {
					names: {
						blockName: "TSTInfo.accuracy"
					}
				}), new asn1js.Boolean({
					name: names.ordering || "TSTInfo.ordering",
					optional: true
				}), new asn1js.Integer({
					name: names.nonce || "TSTInfo.nonce",
					optional: true
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [_GeneralName2.default.schema(names.tsa || {
						names: {
							blockName: "TSTInfo.tsa"
						}
					})]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Repeated({
						name: names.extensions || "TSTInfo.extensions",
						value: _Extension2.default.schema(names.extension || {})
					})]
				}) // IMPLICIT Extensions
				]
			});
		}
	}]);

	return TSTInfo;
}();
//**************************************************************************************


exports.default = TSTInfo;
//# sourceMappingURL=TSTInfo.js.map