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

var ExtKeyUsage = function () {
	//**********************************************************************************
	/**
  * Constructor for ExtKeyUsage class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function ExtKeyUsage() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, ExtKeyUsage);

		//region Internal properties of the object
		/**
   * @type {Array.<string>}
   * @description keyPurposes
   */
		this.keyPurposes = (0, _pvutils.getParametersValue)(parameters, "keyPurposes", ExtKeyUsage.defaultValues("keyPurposes"));
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


	_createClass(ExtKeyUsage, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, ExtKeyUsage.schema({
				names: {
					keyPurposes: "keyPurposes"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for ExtKeyUsage");
			//endregion

			//region Get internal properties from parsed schema
			this.keyPurposes = Array.from(asn1.result.keyPurposes, function (element) {
				return element.valueBlock.toString();
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
				value: Array.from(this.keyPurposes, function (element) {
					return new asn1js.ObjectIdentifier({ value: element });
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
				keyPurposes: Array.from(this.keyPurposes)
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "keyPurposes":
					return [];
				default:
					throw new Error("Invalid member name for ExtKeyUsage class: " + memberName);
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

			// ExtKeyUsage OID ::= 2.5.29.37
			//
			// ExtKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

			// KeyPurposeId ::= OBJECT IDENTIFIER

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [keyPurposes]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.keyPurposes || "",
					value: new asn1js.ObjectIdentifier()
				})]
			});
		}
	}]);

	return ExtKeyUsage;
}();
//**************************************************************************************


exports.default = ExtKeyUsage;
//# sourceMappingURL=ExtKeyUsage.js.map