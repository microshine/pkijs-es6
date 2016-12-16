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

var SecretBag = function () {
	//**********************************************************************************
	/**
  * Constructor for SecretBag class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function SecretBag() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, SecretBag);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description secretTypeId
   */
		this.secretTypeId = (0, _pvutils.getParametersValue)(parameters, "secretTypeId", SecretBag.defaultValues("secretTypeId"));
		/**
   * @type {*}
   * @description secretValue
   */
		this.secretValue = (0, _pvutils.getParametersValue)(parameters, "secretValue", SecretBag.defaultValues("secretValue"));
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


	_createClass(SecretBag, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, SecretBag.schema({
				names: {
					id: "secretTypeId",
					value: "secretValue"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for SecretBag");
			//endregion

			//region Get internal properties from parsed schema
			this.secretTypeId = asn1.result.secretTypeId.valueBlock.toString();
			this.secretValue = asn1.result.secretValue;
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
				value: [new asn1js.ObjectIdentifier({ value: this.secretTypeId }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.secretValue.toSchema()]
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
				secretTypeId: this.secretTypeId,
				secretValue: this.secretValue.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "secretTypeId":
					return "";
				case "secretValue":
					return new asn1js.Any();
				default:
					throw new Error("Invalid member name for SecretBag class: " + memberName);
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
				case "secretTypeId":
					return memberValue === "";
				case "secretValue":
					return memberValue instanceof asn1js.Any;
				default:
					throw new Error("Invalid member name for SecretBag class: " + memberName);
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

			//SecretBag ::= SEQUENCE {
			//    secretTypeId BAG-TYPE.&id ({SecretTypes}),
			//    secretValue  [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}{@secretTypeId})
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [id]
    * @property {string} [value]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.id || "id" }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Any({ name: names.value || "value" })] // EXPLICIT ANY value
				})]
			});
		}
	}]);

	return SecretBag;
}();
//**************************************************************************************


exports.default = SecretBag;
//# sourceMappingURL=SecretBag.js.map