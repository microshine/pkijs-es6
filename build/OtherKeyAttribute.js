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

var OtherKeyAttribute = function () {
	//**********************************************************************************
	/**
  * Constructor for OtherKeyAttribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OtherKeyAttribute() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OtherKeyAttribute);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description keyAttrId
   */
		this.keyAttrId = (0, _pvutils.getParametersValue)(parameters, "keyAttrId", OtherKeyAttribute.defaultValues("keyAttrId"));

		if ("keyAttr" in parameters)
			/**
    * @type {*}
    * @description keyAttr
    */
			this.keyAttr = (0, _pvutils.getParametersValue)(parameters, "keyAttr", OtherKeyAttribute.defaultValues("keyAttr"));
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


	_createClass(OtherKeyAttribute, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OtherKeyAttribute.schema({
				names: {
					keyAttrId: "keyAttrId",
					keyAttr: "keyAttr"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OtherKeyAttribute");
			//endregion

			//region Get internal properties from parsed schema
			this.keyAttrId = asn1.result.keyAttrId.valueBlock.toString();

			if ("keyAttr" in asn1.result) this.keyAttr = asn1.result.keyAttr;
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

			outputArray.push(new asn1js.ObjectIdentifier({ value: this.keyAttrId }));

			if ("keyAttr" in this) outputArray.push(this.keyAttr.toSchema());
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
				keyAttrId: this.keyAttrId
			};

			if ("keyAttr" in this) _object.keyAttr = this.keyAttr.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "keyAttrId":
					return "";
				case "keyAttr":
					return {};
				default:
					throw new Error("Invalid member name for OtherKeyAttribute class: " + memberName);
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
				case "keyAttrId":
					return memberValue === "";
				case "keyAttr":
					return Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for OtherKeyAttribute class: " + memberName);
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

			//OtherKeyAttribute ::= SEQUENCE {
			//    keyAttrId OBJECT IDENTIFIER,
			//    keyAttr ANY DEFINED BY keyAttrId OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [optional]
    * @property {string} [keyAttrId]
    * @property {string} [keyAttr]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				optional: names.optional || true,
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.keyAttrId || "" }), new asn1js.Any({
					optional: true,
					name: names.keyAttr || ""
				})]
			});
		}
	}]);

	return OtherKeyAttribute;
}();
//**************************************************************************************


exports.default = OtherKeyAttribute;
//# sourceMappingURL=OtherKeyAttribute.js.map