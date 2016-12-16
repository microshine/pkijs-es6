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

var ContentInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for ContentInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function ContentInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, ContentInfo);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description contentType
   */
		this.contentType = (0, _pvutils.getParametersValue)(parameters, "contentType", ContentInfo.defaultValues("contentType"));
		/**
   * @type {Any}
   * @description content
   */
		this.content = (0, _pvutils.getParametersValue)(parameters, "content", ContentInfo.defaultValues("content"));
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


	_createClass(ContentInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, ContentInfo.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_CONTENT_INFO");
			//endregion

			//region Get internal properties from parsed schema
			this.contentType = asn1.result.contentType.valueBlock.toString();
			this.content = asn1.result.content;
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
				value: [new asn1js.ObjectIdentifier({ value: this.contentType }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.content] // EXPLICIT ANY value
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
			var object = {
				contentType: this.contentType
			};

			if (!(this.content instanceof asn1js.Any)) object.content = this.content.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "contentType":
					return "";
				case "content":
					return new asn1js.Any();
				default:
					throw new Error("Invalid member name for ContentInfo class: " + memberName);
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
				case "contentType":
					return memberValue === "";
				case "content":
					return memberValue instanceof asn1js.Any;
				default:
					throw new Error("Invalid member name for ContentInfo class: " + memberName);
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

			//ContentInfo ::= SEQUENCE {
			//    contentType ContentType,
			//    content [0] EXPLICIT ANY DEFINED BY contentType }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [contentType]
    * @property {string} [content]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			if ("optional" in names === false) names.optional = false;

			return new asn1js.Sequence({
				name: names.blockName || "ContentInfo",
				optional: names.optional,
				value: [new asn1js.ObjectIdentifier({ name: names.contentType || "contentType" }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Any({ name: names.content || "content" })] // EXPLICIT ANY value
				})]
			});
		}
	}]);

	return ContentInfo;
}();
//**************************************************************************************


exports.default = ContentInfo;
//# sourceMappingURL=ContentInfo.js.map