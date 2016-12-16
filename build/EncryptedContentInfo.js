"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var EncryptedContentInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for EncryptedContentInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function EncryptedContentInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, EncryptedContentInfo);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description contentType
   */
		this.contentType = (0, _pvutils.getParametersValue)(parameters, "contentType", EncryptedContentInfo.defaultValues("contentType"));
		/**
   * @type {AlgorithmIdentifier}
   * @description contentEncryptionAlgorithm
   */
		this.contentEncryptionAlgorithm = (0, _pvutils.getParametersValue)(parameters, "contentEncryptionAlgorithm", EncryptedContentInfo.defaultValues("contentEncryptionAlgorithm"));

		if ("encryptedContent" in parameters) {
			/**
    * @type {OctetString}
    * @description encryptedContent (!!!) could be contructive or primitive value (!!!)
    */
			this.encryptedContent = parameters.encryptedContent;

			if (this.encryptedContent.idBlock.tagClass === 1 && this.encryptedContent.idBlock.tagNumber === 4) {
				//region Divide OCTETSTRING value down to small pieces
				if (this.encryptedContent.idBlock.isConstructed === false) {
					var constrString = new asn1js.OctetString({
						idBlock: { isConstructed: true },
						isConstructed: true
					});

					var offset = 0;
					var length = this.encryptedContent.valueBlock.valueHex.byteLength;

					while (length > 0) {
						var pieceView = new Uint8Array(this.encryptedContent.valueBlock.valueHex, offset, offset + 1024 > this.encryptedContent.valueBlock.valueHex.byteLength ? this.encryptedContent.valueBlock.valueHex.byteLength - offset : 1024);
						var _array = new ArrayBuffer(pieceView.length);
						var _view = new Uint8Array(_array);

						for (var i = 0; i < _view.length; i++) {
							_view[i] = pieceView[i];
						}constrString.valueBlock.value.push(new asn1js.OctetString({ valueHex: _array }));

						length -= pieceView.length;
						offset += pieceView.length;
					}

					this.encryptedContent = constrString;
				}
				//endregion
			}
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


	_createClass(EncryptedContentInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, EncryptedContentInfo.schema({
				names: {
					contentType: "contentType",
					contentEncryptionAlgorithm: {
						names: {
							blockName: "contentEncryptionAlgorithm"
						}
					},
					encryptedContent: "encryptedContent"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for EncryptedContentInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.contentType = asn1.result.contentType.valueBlock.toString();
			this.contentEncryptionAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.contentEncryptionAlgorithm });

			if ("encryptedContent" in asn1.result) {
				this.encryptedContent = asn1.result.encryptedContent;

				this.encryptedContent.idBlock.tagClass = 1; // UNIVERSAL
				this.encryptedContent.idBlock.tagNumber = 4; // OCTETSTRING (!!!) The value still has instance of "in_window.org.pkijs.asn1.ASN1_CONSTRUCTED / ASN1_PRIMITIVE"
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
			//region Create array for output sequence
			var sequenceLengthBlock = {
				isIndefiniteForm: false
			};

			var outputArray = [];

			outputArray.push(new asn1js.ObjectIdentifier({ value: this.contentType }));
			outputArray.push(this.contentEncryptionAlgorithm.toSchema());

			if ("encryptedContent" in this) {
				sequenceLengthBlock.isIndefiniteForm = this.encryptedContent.idBlock.isConstructed;

				var encryptedValue = this.encryptedContent;

				encryptedValue.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				encryptedValue.idBlock.tagNumber = 0; // [0]

				encryptedValue.lenBlock.isIndefiniteForm = this.encryptedContent.idBlock.isConstructed;

				outputArray.push(encryptedValue);
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				lenBlock: sequenceLengthBlock,
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
				contentType: this.contentType,
				contentEncryptionAlgorithm: this.contentEncryptionAlgorithm.toJSON()
			};

			if ("encryptedContent" in this) _object.encryptedContent = this.encryptedContent.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "contentType":
					return "";
				case "contentEncryptionAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "encryptedContent":
					return new asn1js.OctetString();
				default:
					throw new Error("Invalid member name for EncryptedContentInfo class: " + memberName);
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
				case "contentEncryptionAlgorithm":
					return memberValue.algorithmId === "" && "algorithmParams" in memberValue === false;
				case "encryptedContent":
					return memberValue.isEqual(EncryptedContentInfo.defaultValues(memberName));
				default:
					throw new Error("Invalid member name for EncryptedContentInfo class: " + memberName);
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

			//EncryptedContentInfo ::= SEQUENCE {
			//    contentType ContentType,
			//    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
			//    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
			//
			// Comment: Strange, but modern crypto engines create "encryptedContent" as "[0] EXPLICIT EncryptedContent"
			//
			//EncryptedContent ::= OCTET STRING

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [contentType]
    * @property {string} [contentEncryptionAlgorithm]
    * @property {string} [encryptedContent]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.contentType || "" }), _AlgorithmIdentifier2.default.schema(names.contentEncryptionAlgorithm || {}),
				// The CHOICE we need because "EncryptedContent" could have either "constructive"
				// or "primitive" form of encoding and we need to handle both variants
				new asn1js.Choice({
					value: [new asn1js.Constructed({
						name: names.encryptedContent || "",
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [new asn1js.Repeated({
							value: new asn1js.OctetString()
						})]
					}), new asn1js.Primitive({
						name: names.encryptedContent || "",
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						}
					})]
				})]
			});
		}
	}]);

	return EncryptedContentInfo;
}();
//**************************************************************************************


exports.default = EncryptedContentInfo;
//# sourceMappingURL=EncryptedContentInfo.js.map