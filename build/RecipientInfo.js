"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _KeyTransRecipientInfo = require("./KeyTransRecipientInfo");

var _KeyTransRecipientInfo2 = _interopRequireDefault(_KeyTransRecipientInfo);

var _KeyAgreeRecipientInfo = require("./KeyAgreeRecipientInfo");

var _KeyAgreeRecipientInfo2 = _interopRequireDefault(_KeyAgreeRecipientInfo);

var _KEKRecipientInfo = require("./KEKRecipientInfo");

var _KEKRecipientInfo2 = _interopRequireDefault(_KEKRecipientInfo);

var _PasswordRecipientinfo = require("./PasswordRecipientinfo");

var _PasswordRecipientinfo2 = _interopRequireDefault(_PasswordRecipientinfo);

var _OtherRecipientInfo = require("./OtherRecipientInfo");

var _OtherRecipientInfo2 = _interopRequireDefault(_OtherRecipientInfo);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var RecipientInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for RecipientInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function RecipientInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, RecipientInfo);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description variant
   */
		this.variant = (0, _pvutils.getParametersValue)(parameters, "variant", RecipientInfo.defaultValues("variant"));

		if ("value" in parameters)
			/**
    * @type {*}
    * @description value
    */
			this.value = (0, _pvutils.getParametersValue)(parameters, "value", RecipientInfo.defaultValues("value"));
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


	_createClass(RecipientInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, RecipientInfo.schema({
				names: {
					blockName: "blockName"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_RECIPIENT_INFO");
			//endregion

			//region Get internal properties from parsed schema
			if (asn1.result.blockName.idBlock.tagClass === 1) {
				this.variant = 1;
				this.value = new _KeyTransRecipientInfo2.default({ schema: asn1.result.blockName });
			} else {
				//region Create "SEQUENCE" from "ASN1_CONSTRUCTED"
				var tagNumber = asn1.result.blockName.idBlock.tagNumber;

				asn1.result.blockName.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.blockName.idBlock.tagNumber = 16; // SEQUENCE
				//endregion

				switch (tagNumber) {
					case 1:
						this.variant = 2;
						this.value = new _KeyAgreeRecipientInfo2.default({ schema: asn1.result.blockName });
						break;
					case 2:
						this.variant = 3;
						this.value = new _KEKRecipientInfo2.default({ schema: asn1.result.blockName });
						break;
					case 3:
						this.variant = 4;
						this.value = new _PasswordRecipientinfo2.default({ schema: asn1.result.blockName });
						break;
					case 4:
						this.variant = 5;
						this.value = new _OtherRecipientInfo2.default({ schema: asn1.result.blockName });
						break;
					default:
						throw new Error("Incorrect structure of RecipientInfo block");
				}
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
			var _schema = this.value.toSchema();

			switch (this.variant) {
				case 1:
					return _schema;
				case 2:
				case 3:
				case 4:
					//region Create "ASN1_CONSTRUCTED" from "SEQUENCE"
					_schema.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
					_schema.idBlock.tagNumber = this.variant - 1;
					//endregion

					return _schema;
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

			if (this.variant >= 1 && this.variant <= 4) _object.value = this.value.toJSON();

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
					throw new Error("Invalid member name for RecipientInfo class: " + memberName);
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
					return memberValue === RecipientInfo.defaultValues(memberName);
				case "value":
					return Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for RecipientInfo class: " + memberName);
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

			//RecipientInfo ::= CHOICE {
			//    ktri KeyTransRecipientInfo,
			//    kari [1] KeyAgreeRecipientInfo,
			//    kekri [2] KEKRecipientInfo,
			//    pwri [3] PasswordRecipientinfo,
			//    ori [4] OtherRecipientInfo }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [type]
    * @property {string} [setName]
    * @property {string} [values]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Choice({
				value: [_KeyTransRecipientInfo2.default.schema({
					names: {
						blockName: names.blockName || ""
					}
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: _KeyAgreeRecipientInfo2.default.schema().valueBlock.value
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					value: _KEKRecipientInfo2.default.schema().valueBlock.value
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					value: _PasswordRecipientinfo2.default.schema().valueBlock.value
				}), new asn1js.Constructed({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					},
					value: _OtherRecipientInfo2.default.schema().valueBlock.value
				})]
			});
		}
	}]);

	return RecipientInfo;
}();
//**************************************************************************************


exports.default = RecipientInfo;
//# sourceMappingURL=RecipientInfo.js.map