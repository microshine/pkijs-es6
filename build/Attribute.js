"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var Attribute = function () {
	//**********************************************************************************
	/**
  * Constructor for Attribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Attribute() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Attribute);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description type
   */
		this.type = (0, _pvutils.getParametersValue)(parameters, "type", Attribute.defaultValues("type"));
		/**
   * @type {Array}
   * @description values
   */
		this.values = (0, _pvutils.getParametersValue)(parameters, "values", Attribute.defaultValues("values"));
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


	_createClass(Attribute, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Attribute.schema({
				names: {
					type: "type",
					values: "values"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for ATTRIBUTE");
			//endregion

			//region Get internal properties from parsed schema
			this.type = asn1.result.type.valueBlock.toString();
			this.values = asn1.result.values;
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
				value: [new asn1js.ObjectIdentifier({ value: this.type }), new asn1js.Set({
					value: this.values
				})]
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
				type: this.type,
				values: Array.from(this.values, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "type":
					return "";
				case "values":
					return [];
				default:
					throw new Error("Invalid member name for Attribute class: " + memberName);
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
					return memberValue === "";
				case "values":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for Attribute class: " + memberName);
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

			// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
			//    type   ATTRIBUTE.&id({IOSet}),
			//    values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [type]
    * @property {string} [setName]
    * @property {string} [values]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.type || "" }), new asn1js.Set({
					name: names.setName || "",
					value: [new asn1js.Repeated({
						name: names.values || "",
						value: new asn1js.Any()
					})]
				})]
			});
		}
	}]);

	return Attribute;
}();
//**************************************************************************************


exports.default = Attribute;
//# sourceMappingURL=Attribute.js.map