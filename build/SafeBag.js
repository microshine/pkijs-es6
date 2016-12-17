"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _PrivateKeyInfo = require("./PrivateKeyInfo");

var _PrivateKeyInfo2 = _interopRequireDefault(_PrivateKeyInfo);

var _PKCS8ShroudedKeyBag = require("./PKCS8ShroudedKeyBag");

var _PKCS8ShroudedKeyBag2 = _interopRequireDefault(_PKCS8ShroudedKeyBag);

var _CertBag = require("./CertBag");

var _CertBag2 = _interopRequireDefault(_CertBag);

var _CRLBag = require("./CRLBag");

var _CRLBag2 = _interopRequireDefault(_CRLBag);

var _SecretBag = require("./SecretBag");

var _SecretBag2 = _interopRequireDefault(_SecretBag);

var _SafeContents = require("./SafeContents");

var _SafeContents2 = _interopRequireDefault(_SafeContents);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var SafeBag = function () {
	//**********************************************************************************
	/**
  * Constructor for SafeBag class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function SafeBag() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, SafeBag);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description bagId
   */
		this.bagId = (0, _pvutils.getParametersValue)(parameters, "bagId", SafeBag.defaultValues("bagId"));
		/**
   * @type {*}
   * @description bagValue
   */
		this.bagValue = (0, _pvutils.getParametersValue)(parameters, "bagValue", SafeBag.defaultValues("bagValue"));

		if ("bagAttributes" in parameters) {
			/**
    * @type {Array.<Attribute>}
    * @description bagAttributes
    */
			this.bagAttributes = (0, _pvutils.getParametersValue)(parameters, "bagAttributes", SafeBag.defaultValues("bagAttributes"));
		}
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


	_createClass(SafeBag, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, SafeBag.schema({
				names: {
					bagId: "bagId",
					bagValue: "bagValue",
					bagAttributes: "bagAttributes"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for SafeBag");
			//endregion

			//region Get internal properties from parsed schema
			this.bagId = asn1.result.bagId.value_block.toString();

			switch (this.bagId) {
				case "1.2.840.113549.1.12.10.1.1":
					// keyBag
					this.bagValue = new _PrivateKeyInfo2.default({ schema: asn1.result.bagValue });
					break;
				case "1.2.840.113549.1.12.10.1.2":
					// pkcs8ShroudedKeyBag
					this.bagValue = new _PKCS8ShroudedKeyBag2.default({ schema: asn1.result.bagValue });
					break;
				case "1.2.840.113549.1.12.10.1.3":
					// certBag
					this.bagValue = new _CertBag2.default({ schema: asn1.result.bagValue });
					break;
				case "1.2.840.113549.1.12.10.1.4":
					// crlBag
					this.bagValue = new _CRLBag2.default({ schema: asn1.result.bagValue });
					break;
				case "1.2.840.113549.1.12.10.1.5":
					// secretBag
					this.bagValue = new _SecretBag2.default({ schema: asn1.result.bagValue });
					break;
				case "1.2.840.113549.1.12.10.1.6":
					// safeContentsBag
					this.bagValue = new _SafeContents2.default({ schema: asn1.result.bagValue });
					break;
				default:
					throw new Error("Invalid \"bagId\" for SafeBag: " + this.bagId);
			}

			if ("bagAttributes" in asn1.result) this.bagAttributes = Array.from(asn1.result.bagAttributes, function (element) {
				return new _Attribute2.default({ schema: element });
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
			var outputArray = [new asn1js.ObjectIdentifier({ value: this.bagId }), new asn1js.Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [this.bagValue.toSchema()]
			})];

			if ("bagAttributes" in this) {
				outputArray.push(new asn1js.Set({
					value: Array.from(this.bagAttributes, function (element) {
						return element.toSchema();
					})
				}));
			}

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
			var output = {
				bagId: this.bagId,
				bagValue: this.bagValue.toJSON()
			};

			if ("bagAttributes" in this) output.bagAttributes = Array.from(this.bagAttributes, function (element) {
				return element.toJSON();
			});

			return output;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "bagId":
					return "";
				case "bagValue":
					return new asn1js.Any();
				case "bagAttributes":
					return [];
				default:
					throw new Error("Invalid member name for SafeBag class: " + memberName);
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
				case "bagId":
					return memberValue === "";
				case "bagValue":
					return memberValue instanceof asn1js.Any;
				case "bagAttributes":
					return memberValue.length === 0;
				default:
					throw new Error("Invalid member name for SafeBag class: " + memberName);
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

			//SafeBag ::= SEQUENCE {
			//    bagId	      	BAG-TYPE.&id ({PKCS12BagSet}),
			//    bagValue      [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
			//    bagAttributes SET OF PKCS12Attribute OPTIONAL
			//}

			//rsadsi	OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549)}
			//pkcs    OBJECT IDENTIFIER ::= {rsadsi pkcs(1)}
			//pkcs-12	OBJECT IDENTIFIER ::= {pkcs 12}

			//bagtypes			OBJECT IDENTIFIER ::= {pkcs-12 10 1}

			//keyBag 	  BAG-TYPE ::=
			//{KeyBag IDENTIFIED BY {bagtypes 1}}
			//pkcs8ShroudedKeyBag BAG-TYPE ::=
			//{PKCS8ShroudedKeyBag IDENTIFIED BY {bagtypes 2}}
			//certBag BAG-TYPE ::=
			//{CertBag IDENTIFIED BY {bagtypes 3}}
			//crlBag BAG-TYPE ::=
			//{CRLBag IDENTIFIED BY {bagtypes 4}}
			//secretBag BAG-TYPE ::=
			//{SecretBag IDENTIFIED BY {bagtypes 5}}
			//safeContentsBag BAG-TYPE ::=
			//{SafeContents IDENTIFIED BY {bagtypes 6}}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [bagId]
    * @property {string} [bagValue]
    * @property {string} [bagAttributes]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.bagId || "bagId" }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Any({ name: names.bagValue || "bagValue" })] // EXPLICIT ANY value
				}), new asn1js.Set({
					optional: true,
					value: [new asn1js.Repeated({
						name: names.bagAttributes || "bagAttributes",
						value: _Attribute2.default.schema()
					})]
				})]
			});
		}
	}]);

	return SafeBag;
}();
//**************************************************************************************


exports.default = SafeBag;
//# sourceMappingURL=SafeBag.js.map