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

var _RecipientKeyIdentifier = require("./RecipientKeyIdentifier");

var _RecipientKeyIdentifier2 = _interopRequireDefault(_RecipientKeyIdentifier);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var KeyAgreeRecipientIdentifier = function () {
	//**********************************************************************************
	/**
  * Constructor for KeyAgreeRecipientIdentifier class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function KeyAgreeRecipientIdentifier() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, KeyAgreeRecipientIdentifier);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description variant
   */
		this.variant = (0, _pvutils.getParametersValue)(parameters, "variant", KeyAgreeRecipientIdentifier.defaultValues("variant"));
		/**
   * @type {*}
   * @description values
   */
		this.value = (0, _pvutils.getParametersValue)(parameters, "value", KeyAgreeRecipientIdentifier.defaultValues("value"));
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


	_createClass(KeyAgreeRecipientIdentifier, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, KeyAgreeRecipientIdentifier.schema({
				names: {
					blockName: "blockName"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for KeyAgreeRecipientIdentifier");
			//endregion

			//region Get internal properties from parsed schema
			if (asn1.result.blockName.idBlock.tagClass === 1) {
				this.variant = 1;
				this.value = new _IssuerAndSerialNumber2.default({ schema: asn1.result.blockName });
			} else {
				this.variant = 2;

				asn1.result.blockName.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.blockName.idBlock.tagNumber = 16; // SEQUENCE

				this.value = new _RecipientKeyIdentifier2.default({ schema: asn1.result.blockName });
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
						value: this.value.toSchema().valueBlock.value
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
					throw new Error("Invalid member name for KeyAgreeRecipientIdentifier class: " + memberName);
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
				case "value":
					return Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for KeyAgreeRecipientIdentifier class: " + memberName);
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

			//KeyAgreeRecipientIdentifier ::= CHOICE {
			//    issuerAndSerialNumber IssuerAndSerialNumber,
			//    rKeyId [0] IMPLICIT RecipientKeyIdentifier }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [issuerAndSerialNumber]
    * @property {string} [rKeyId]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Choice({
				value: [_IssuerAndSerialNumber2.default.schema(names.issuerAndSerialNumber || {
					names: {
						blockName: names.blockName || ""
					}
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: _RecipientKeyIdentifier2.default.schema(names.rKeyId || {
						names: {
							blockName: names.blockName || ""
						}
					}).valueBlock.value
				})]
			});
		}
	}]);

	return KeyAgreeRecipientIdentifier;
}();
//**************************************************************************************


exports.default = KeyAgreeRecipientIdentifier;
//# sourceMappingURL=KeyAgreeRecipientIdentifier.js.map