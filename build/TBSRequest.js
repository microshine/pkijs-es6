"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _GeneralName = require("./GeneralName");

var _GeneralName2 = _interopRequireDefault(_GeneralName);

var _Request = require("./Request");

var _Request2 = _interopRequireDefault(_Request);

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

var _Extensions = require("./Extensions");

var _Extensions2 = _interopRequireDefault(_Extensions);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var TBSRequest = function () {
	//**********************************************************************************
	/**
  * Constructor for TBSRequest class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function TBSRequest() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, TBSRequest);

		//region Internal properties of the object
		/**
   * @type {ArrayBuffer}
   * @description tbs
   */
		this.tbs = (0, _pvutils.getParametersValue)(parameters, "tbs", TBSRequest.defaultValues("tbs"));

		if ("version" in parameters)
			/**
    * @type {number}
    * @description version
    */
			this.version = (0, _pvutils.getParametersValue)(parameters, "version", TBSRequest.defaultValues("version"));

		if ("requestorName" in parameters)
			/**
    * @type {GeneralName}
    * @description requestorName
    */
			this.requestorName = (0, _pvutils.getParametersValue)(parameters, "requestorName", TBSRequest.defaultValues("requestorName"));

		/**
   * @type {Array.<Request>}
   * @description requestList
   */
		this.requestList = (0, _pvutils.getParametersValue)(parameters, "requestList", TBSRequest.defaultValues("requestList"));

		if ("requestExtensions" in parameters)
			/**
    * @type {Array.<Extension>}
    * @description requestExtensions
    */
			this.requestExtensions = (0, _pvutils.getParametersValue)(parameters, "requestExtensions", TBSRequest.defaultValues("requestExtensions"));
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


	_createClass(TBSRequest, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, TBSRequest.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for TBSRequest");
			//endregion

			//region Get internal properties from parsed schema
			this.tbs = asn1.result.TBSRequest.valueBeforeDecode;

			if ("TBSRequest.version" in asn1.result) this.version = asn1.result["TBSRequest.version"].valueBlock.valueDec;
			if ("TBSRequest.requestorName" in asn1.result) this.requestorName = new _GeneralName2.default({ schema: asn1.result["TBSRequest.requestorName"] });

			this.requestList = Array.from(asn1.result["TBSRequest.requests"], function (element) {
				return new _Request2.default({ schema: element });
			});

			if ("TBSRequest.requestExtensions" in asn1.result) this.requestExtensions = Array.from(asn1.result["TBSRequest.requestExtensions"].valueBlock.value, function (element) {
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
				if (this.tbs.byteLength === 0) // No stored TBS part
					return TBSRequest.schema();

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

					if ("requestorName" in this) {
						outputArray.push(new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: [this.requestorName.toSchema()]
						}));
					}

					outputArray.push(new asn1js.Sequence({
						value: Array.from(this.requestList, function (element) {
							return element.toSchema();
						})
					}));

					if ("requestExtensions" in this) {
						outputArray.push(new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 2 // [2]
							},
							value: [new asn1js.Sequence({
								value: Array.from(this.requestExtensions, function (element) {
									return element.toSchema();
								})
							})]
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

			if ("requestorName" in this) _object.requestorName = this.requestorName.toJSON();

			_object.requestList = Array.from(this.requestList, function (element) {
				return element.toJSON();
			});

			if ("requestExtensions" in this) _object.requestExtensions = Array.from(this.requestExtensions, function (element) {
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
				case "version":
					return 0;
				case "requestorName":
					return new _GeneralName2.default();
				case "requestList":
				case "requestExtensions":
					return [];
				default:
					throw new Error("Invalid member name for TBSRequest class: " + memberName);
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
				case "version":
					return memberValue === TBSRequest.defaultValues(memberName);
				case "requestorName":
					return memberValue.type === _GeneralName2.default.defaultValues("type") && Object.keys(memberValue.value).length === 0;
				case "requestList":
				case "requestExtensions":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for TBSRequest class: " + memberName);
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

			//TBSRequest      ::=     SEQUENCE {
			//    version             [0]     EXPLICIT Version DEFAULT v1,
			//    requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
			//    requestList                 SEQUENCE OF Request,
			//    requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [TBSRequestVersion]
    * @property {string} [requestorName]
    * @property {string} [requestList]
    * @property {string} [requests]
    * @property {string} [requestNames]
    * @property {string} [extensions]
    * @property {string} [requestExtensions]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "TBSRequest",
				value: [new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Integer({ name: names.TBSRequestVersion || "TBSRequest.version" })]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [_GeneralName2.default.schema(names.requestorName || {
						names: {
							blockName: "TBSRequest.requestorName"
						}
					})]
				}), new asn1js.Sequence({
					name: names.requestList || "TBSRequest.requestList",
					value: [new asn1js.Repeated({
						name: names.requests || "TBSRequest.requests",
						value: _Request2.default.schema(names.requestNames || {})
					})]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					value: [_Extensions2.default.schema(names.extensions || {
						names: {
							blockName: names.requestExtensions || "TBSRequest.requestExtensions"
						}
					})]
				})]
			});
		}
	}]);

	return TBSRequest;
}();
//**************************************************************************************


exports.default = TBSRequest;
//# sourceMappingURL=TBSRequest.js.map