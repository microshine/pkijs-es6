"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var RecipientIdentifier = function () {
	//**********************************************************************************
	/**
  * Constructor for RecipientIdentifier class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function RecipientIdentifier() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, RecipientIdentifier);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description variant
   */
		this.variant = (0, _pvutils.getParametersValue)(parameters, "variant", RecipientIdentifier.defaultValues("variant"));

		if ("value" in parameters)
			/**
    * @type {*}
    * @description value
    */
			this.value = (0, _pvutils.getParametersValue)(parameters, "value", RecipientIdentifier.defaultValues("value"));
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


	_createClass(RecipientIdentifier, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, RecipientIdentifier.schema({
				names: {
					blockName: "blockName"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for RecipientIdentifier");
			//endregion

			//region Get internal properties from parsed schema
			if (asn1.result.blockName.idBlock.tagClass === 1) {
				this.variant = 1;
				this.value = new _IssuerAndSerialNumber2.default({ schema: asn1.result.blockName });
			} else {
				this.variant = 2;
				this.value = asn1.result.blockName.valueBlock.value[0];
			}
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
			switch (this.variant) {
				case 1:
					return this.value.toSchema();
				case 2:
					return new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [this.value]
					});
				default:
					return new asn1js.Any();
			}
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
				variant: this.variant
			};

			if (this.variant === 1 || this.variant === 2) _object.value = this.value.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "variant":
					return -1;
				case "value":
					return {};
				default:
					throw new Error("Invalid member name for RecipientIdentifier class: " + memberName);
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
				case "variant":
					return memberValue === -1;
				case "values":
					return Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for RecipientIdentifier class: " + memberName);
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

			//RecipientIdentifier ::= CHOICE {
			//    issuerAndSerialNumber IssuerAndSerialNumber,
			//    subjectKeyIdentifier [0] SubjectKeyIdentifier }
			//
			//SubjectKeyIdentifier ::= OCTET STRING

			/**
    * @type {Object}
    * @property {string} [blockName]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Choice({
				value: [_IssuerAndSerialNumber2.default.schema({
					names: {
						blockName: names.blockName || ""
					}
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.OctetString()]
				})]
			});
		}
	}]);

	return RecipientIdentifier;
}();
//**************************************************************************************


exports.default = RecipientIdentifier;
//# sourceMappingURL=RecipientIdentifier.js.map