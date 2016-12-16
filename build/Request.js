"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _CertID = require("./CertID");

var _CertID2 = _interopRequireDefault(_CertID);

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var Request = function () {
	//**********************************************************************************
	/**
  * Constructor for Request class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Request() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Request);

		//region Internal properties of the object
		/**
   * @type {CertID}
   * @description reqCert
   */
		this.reqCert = (0, _pvutils.getParametersValue)(parameters, "reqCert", Request.defaultValues("reqCert"));

		if ("singleRequestExtensions" in parameters)
			/**
    * @type {Array.<Extension>}
    * @description singleRequestExtensions
    */
			this.singleRequestExtensions = (0, _pvutils.getParametersValue)(parameters, "singleRequestExtensions", Request.defaultValues("singleRequestExtensions"));
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


	_createClass(Request, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Request.schema({
				names: {
					reqCert: {
						names: {
							blockName: "reqCert"
						}
					},
					singleRequestExtensions: {
						names: {
							blockName: "singleRequestExtensions"
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for Request");
			//endregion

			//region Get internal properties from parsed schema
			this.reqCert = new _CertID2.default({ schema: asn1.result.reqCert });

			if ("singleRequestExtensions" in asn1.result) this.singleRequestExtensions = Array.from(asn1.result.singleRequestExtensions.valueBlock.value, function (element) {
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

			outputArray.push(this.reqCert.toSchema());

			if ("singleRequestExtensions" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.singleRequestExtensions, function (element) {
							return element.toSchema();
						})
					})]
				}));
			}
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
				reqCert: this.reqCert.toJSON()
			};

			if ("singleRequestExtensions" in this) _object.singleRequestExtensions = Array.from(this.singleRequestExtensions, function (element) {
				return element.toJSON();
			});

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "reqCert":
					return new _CertID2.default();
				case "singleRequestExtensions":
					return [];
				default:
					throw new Error("Invalid member name for Request class: " + memberName);
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
				case "reqCert":
					return memberValue.isEqual(Request.defaultValues(memberName));
				case "singleRequestExtensions":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for Request class: " + memberName);
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

			//Request         ::=     SEQUENCE {
			//    reqCert                     CertID,
			//    singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [reqCert]
    * @property {string} [extensions]
    * @property {string} [singleRequestExtensions]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [_CertID2.default.schema(names.reqCert || {}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [_Extension2.default.schema(names.extensions || {
						names: {
							blockName: names.singleRequestExtensions || ""
						}
					})]
				})]
			});
		}
	}]);

	return Request;
}();
//**************************************************************************************


exports.default = Request;
//# sourceMappingURL=Request.js.map