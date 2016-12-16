"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _Extension = require("./Extension");

var _Extension2 = _interopRequireDefault(_Extension);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var Extensions = function () {
	//**********************************************************************************
	/**
  * Constructor for Extensions class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Extensions() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Extensions);

		//region Internal properties of the object
		/**
   * @type {Array.<Extension>}
   * @description type
   */
		this.extensions = (0, _pvutils.getParametersValue)(parameters, "extensions", Extensions.defaultValues("extensions"));
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


	_createClass(Extensions, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Extensions.schema({
				names: {
					extensions: "extensions"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for EXTENSIONS");
			//endregion

			//region Get internal properties from parsed schema
			this.extensions = Array.from(asn1.result.extensions, function (element) {
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
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: Array.from(this.extensions, function (element) {
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
				extensions: Array.from(this.extensions, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "extensions":
					return [];
				default:
					throw new Error("Invalid member name for Extensions class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @param {boolean} optional Flag that current schema should be optional
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];
			var optional = arguments.length <= 1 || arguments[1] === undefined ? false : arguments[1];

			//Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [extensions]
    * @property {string} [extension]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				optional: optional,
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.extensions || "",
					value: _Extension2.default.schema(names.extension || {})
				})]
			});
		}
	}]);

	return Extensions;
}();
//**************************************************************************************


exports.default = Extensions;
//# sourceMappingURL=Extensions.js.map