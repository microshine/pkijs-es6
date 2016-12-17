"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

var _SingleResponse = require("./SingleResponse");

var _SingleResponse2 = _interopRequireDefault(_SingleResponse);

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

var _Extensions = require("./Extensions");

var _Extensions2 = _interopRequireDefault(_Extensions);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var ResponseData = function () {
	//**********************************************************************************
	/**
  * Constructor for ResponseData class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function ResponseData() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, ResponseData);

		//region Internal properties of the object
		/**
   * @type {ArrayBuffer}
   * @description tbs
   */
		this.tbs = (0, _pvutils.getParametersValue)(parameters, "tbs", ResponseData.defaultValues("tbs"));
		/**
   * @type {Object}
   * @description responderID
   */
		this.responderID = (0, _pvutils.getParametersValue)(parameters, "responderID", ResponseData.defaultValues("responderID"));
		/**
   * @type {Date}
   * @description producedAt
   */
		this.producedAt = (0, _pvutils.getParametersValue)(parameters, "producedAt", ResponseData.defaultValues("producedAt"));
		/**
   * @type {Array.<SingleResponse>}
   * @description responses
   */
		this.responses = (0, _pvutils.getParametersValue)(parameters, "responses", ResponseData.defaultValues("responses"));

		if ("responseExtensions" in parameters)
			/**
    * @type {Array.<Extension>}
    * @description responseExtensions
    */
			this.responseExtensions = (0, _pvutils.getParametersValue)(parameters, "responseExtensions", ResponseData.defaultValues("responseExtensions"));
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


	_createClass(ResponseData, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, ResponseData.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for ocsp.ResponseData");
			//endregion

			//region Get internal properties from parsed schema
			this.tbs = asn1.result.ResponseData.valueBeforeDecode;

			if ("ResponseData.version" in asn1.result) this.version = asn1.result["ResponseData.version"].valueBlock.valueDec;

			if (asn1.result["ResponseData.responderID"].idBlock.tagNumber === 1) this.responderID = new _RelativeDistinguishedNames2.default({ schema: asn1.result["ResponseData.responderID"].valueBlock.value[0] });else this.responderID = asn1.result["ResponseData.responderID"].valueBlock.value[0]; // OCTETSTRING

			this.producedAt = asn1.result["ResponseData.producedAt"].toDate();
			this.responses = Array.from(asn1.result["ResponseData.responses"], function (element) {
				return new _SingleResponse2.default({ schema: element });
			});

			if ("ResponseData.responseExtensions" in asn1.result) this.responseExtensions = Array.from(asn1.result["ResponseData.responseExtensions"].valueBlock.value, function (element) {
				return new _Extension2.default({ schema: element });
			});
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

			//region Decode stored TBS value
			var tbsSchema = void 0;

			if (encodeFlag === false) {
				if (this.tbs.length === 0) // No stored certificate TBS part
					return ResponseData.schema();

				tbsSchema = asn1js.fromBER(this.tbs).result;
			}
			//endregion
			//region Create TBS schema via assembling from TBS parts
			else {
					var outputArray = [];

					if ("version" in this) {
						outputArray.push(new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							},
							value: [new asn1js.Integer({ value: this.version })]
						}));
					}

					if (this.responderID instanceof _RelativeDistinguishedNames2.default) {
						outputArray.push(new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: [this.responderID.toSchema()]
						}));
					} else {
						outputArray.push(new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 2 // [2]
							},
							value: [this.responderID]
						}));
					}

					outputArray.push(new asn1js.GeneralizedTime({ valueDate: this.producedAt }));

					outputArray.push(new asn1js.Sequence({
						value: Array.from(this.responses, function (element) {
							return element.toSchema();
						})
					}));

					if ("responseExtensions" in this) {
						outputArray.push(new asn1js.Sequence({
							value: Array.from(this.responseExtensions, function (element) {
								return element.toSchema();
							})
						}));
					}

					tbsSchema = new asn1js.Sequence({
						value: outputArray
					});
				}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return tbsSchema;
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
			var _object = {};

			if ("version" in this) _object.version = this.version;

			if ("responderID" in this) _object.responderID = this.responderID;

			if ("producedAt" in this) _object.producedAt = this.producedAt;

			if ("responses" in this) _object.responses = Array.from(this.responses, function (element) {
				return element.toJSON();
			});

			if ("responseExtensions" in this) _object.responseExtensions = Array.from(this.responseExtensions, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "tbs":
					return new ArrayBuffer(0);
				case "responderID":
					return {};
				case "producedAt":
					return new Date(0, 0, 0);
				case "responses":
				case "responseExtensions":
					return [];
				default:
					throw new Error("Invalid member name for ResponseData class: " + memberName);
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
				case "tbs":
					return memberValue.byteLength === 0;
				case "responderID":
					return Object.keys(memberValue).length === 0;
				case "producedAt":
					return memberValue === ResponseData.defaultValues(memberName);
				case "responses":
				case "responseExtensions":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for ResponseData class: " + memberName);
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

			//ResponseData ::= SEQUENCE {
			//    version              [0] EXPLICIT Version DEFAULT v1,
			//    responderID              ResponderID,
			//    producedAt               GeneralizedTime,
			//    responses                SEQUENCE OF SingleResponse,
			//    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [ResponseDataByName]
    * @property {string} [ResponseDataByKey]
    * @property {string} [producedAt]
    * @property {string} [response]
    * @property {string} [extensions]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "ResponseData",
				value: [new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Integer({ name: names.version || "ResponseData.version" })]
				}), new asn1js.Choice({
					value: [new asn1js.Constructed({
						name: names.responderID || "ResponseData.responderID",
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 1 // [1]
						},
						value: [_RelativeDistinguishedNames2.default.schema(names.ResponseDataByName || {
							names: {
								blockName: "ResponseData.byName"
							}
						})]
					}), new asn1js.Constructed({
						name: names.responderID || "ResponseData.responderID",
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 2 // [2]
						},
						value: [new asn1js.OctetString({ name: names.ResponseDataByKey || "ResponseData.byKey" })]
					})]
				}), new asn1js.GeneralizedTime({ name: names.producedAt || "ResponseData.producedAt" }), new asn1js.Sequence({
					value: [new asn1js.Repeated({
						name: "ResponseData.responses",
						value: _SingleResponse2.default.schema(names.response || {})
					})]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [_Extensions2.default.schema(names.extensions || {
						names: {
							blockName: "ResponseData.responseExtensions"
						}
					})]
				}) // EXPLICIT SEQUENCE value
				]
			});
		}
	}]);

	return ResponseData;
}();
//**************************************************************************************


exports.default = ResponseData;
//# sourceMappingURL=ResponseData.js.map